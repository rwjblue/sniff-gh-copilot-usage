use anyhow::{Context, Result};
use clap::Parser;
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Mutex;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(about = "Monitor usage of domains ending in githubcopilot.com")]
struct Cli {
    /// Network interface to listen on
    #[arg(short, long)]
    interface: Option<String>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")),
        )
        .init();

    let cli = Cli::parse();
    debug!(?cli, "starting monitor");

    let lookup_counts = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
    let ip_to_domain = get_initial_ip_to_domain_mapping()?;
    let running = Arc::new(AtomicBool::new(true));
    let running_ctrl_c = Arc::clone(&running);
    ctrlc::set_handler(move || {
        info!("Received Ctrl-C!");
        running_ctrl_c.store(false, Ordering::Relaxed);
        info!(
            "Set running to false: {}",
            running_ctrl_c.load(Ordering::Relaxed)
        );
    })?;

    debug!("Registered Ctrl-C handler");

    let interface = cli.interface.unwrap_or_else(|| {
        get_default_interface()
            .context("Failed to detect default interface")
            .unwrap_or_else(|e| {
                eprintln!("Warning: {}, falling back to en0", e);
                "en0".to_string()
            })
    });

    let lookup_counts_ref = Arc::clone(&lookup_counts);
    let running_ref = Arc::clone(&running);

    let (error_tx, error_rx) = std::sync::mpsc::channel();
    debug!(interface = ?interface, "starting packet capture");

    let capture_thread = thread::spawn(move || -> Result<()> {
        if let Err(e) = capture_packets(interface, lookup_counts_ref, ip_to_domain, running_ref) {
            error_tx.send(e).expect("Failed to send error");
        }

        Ok(())
    });

    while running.load(Ordering::Relaxed) {
        if let Ok(error) = error_rx.try_recv() {
            error!(error = %error, "received capture error");
            running.store(false, Ordering::Relaxed);
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    debug!("initiating shutdown");
    running.store(false, Ordering::Relaxed);
    capture_thread.join().map_err(|e| {
        error!(?e, "capture thread panicked");
        anyhow::anyhow!("capture thread panicked: {:?}", e)
    })??;

    info!("monitor completed successfully");
    println!("\n\n");

    print_lookup_table(&lookup_counts);
    Ok(())
}

fn get_default_interface() -> Result<String> {
    Device::list()
        .map_err(|e| anyhow::anyhow!("failed to list devices: {}", e))?
        .into_iter()
        .next()
        .map(|dev| dev.name)
        .ok_or_else(|| anyhow::anyhow!("no capture devices found"))
}

fn get_initial_ip_to_domain_mapping() -> Result<HashMap<IpAddr, String>> {
    let hostnames = vec![
        "api.githubcopilot.com",
        "api.enterprise.githubcopilot.com",
        "api.individual.githubcopilot.com",
        "api.githubcopilot.com",
        "proxy.enterprise.githubcopilot.com",
        "proxy.individual.githubcopilot.com",
    ];

    let mut ip_to_domain = HashMap::new();

    for hostname in hostnames {
        let socket_addr = format!("{}:443", hostname);
        let addrs = socket_addr
            .to_socket_addrs()
            .with_context(|| format!("Failed to resolve hostname: {}", hostname))?;

        for addr in addrs {
            ip_to_domain.insert(addr.ip(), hostname.to_string());
        }
    }

    Ok(ip_to_domain)
}

fn capture_packets(
    interface: String,
    lookup_counts_ref: Arc<Mutex<HashMap<String, usize>>>,
    mut ip_to_domain: HashMap<IpAddr, String>,
    running_ref: Arc<AtomicBool>,
) -> Result<()> {
    debug!("attempting to open capture device: {}", interface);

    let device = match Capture::from_device(interface.as_str()) {
        Ok(device) => {
            debug!("device opened, configuring capture");
            device
        }
        Err(e) => {
            error!("failed to open device {}: {}", interface, e);
            return Err(anyhow::anyhow!("failed to open capture device: {}", e));
        }
    };

    let mut capture = match device
        .promisc(true)
        .timeout(100)
        .immediate_mode(true)
        .open()
    {
        Ok(cap) => {
            debug!("capture configured successfully");
            cap
        }
        Err(e) => {
            error!("failed to start capture: {}", e);
            return Err(anyhow::anyhow!("failed to start capture: {}", e));
        }
    };

    info!("packet capture started successfully");

    capture
        .filter("port 53 or port 80 or port 443", true)
        .context("setting capture filter")?;

    while running_ref.load(Ordering::Relaxed) {
        match capture.next_packet() {
            Ok(packet) => {
                if let Some((domain, ips)) = extract_githubcopilot_domain(packet.data) {
                    info!(domain = %domain, "detected GitHub Copilot DNS lookup");
                    increment_counter(&lookup_counts_ref, domain.clone())?;

                    if !ips.is_empty() {
                        // Add each resolved IP as a key mapping to this domain
                        for ip in ips {
                            ip_to_domain.insert(ip, domain.clone());
                        }
                        info!(domain = %domain, "recorded DNS resolution");
                    }
                }

                // Process HTTP/HTTPS packets
                if let Some(payload) = skip_network_headers(packet.data) {
                    let dest_ip = extract_dest_ip(packet.data)?;

                    // Check if this IP belongs to any githubcopilot domain
                    if let Some(domain) = ip_to_domain.get(&dest_ip) {
                        info!(domain = %domain, "detected GitHub Copilot HTTP access");
                        increment_counter(&lookup_counts_ref, domain.clone())?;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Timeout is expected, just continue the loop
                continue;
            }
            Err(e) => {
                error!(error = %e, "packet capture error");

                return Err(anyhow::anyhow!("packet capture error: {}", e));
            }
        }
    }
    debug!("capture thread shutting down");
    Ok(())
}

fn extract_dest_ip(packet_data: &[u8]) -> Result<IpAddr> {
    if packet_data.len() < 34 {
        return Err(anyhow::anyhow!("packet too short"));
    }

    // Skip Ethernet header (14 bytes) and read destination IP
    let ip_header = &packet_data[14..];
    let dest_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        ip_header[16],
        ip_header[17],
        ip_header[18],
        ip_header[19],
    ));

    Ok(dest_ip)
}

/// Extracts domain from a DNS packet if it matches `githubcopilot.com`
fn extract_githubcopilot_domain(packet_data: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    // Skip Ethernet header (14 bytes) and IP header (20 bytes)
    if packet_data.len() < 42 {
        // 14 + 20 + 8 (UDP header)
        return None;
    }

    let dns_start = match get_dns_offset(packet_data) {
        Some(offset) => offset,
        None => return None,
    };

    if packet_data.len() < dns_start + 12 {
        return None;
    }

    // Parse DNS packet
    match dns_parser::Packet::parse(&packet_data[dns_start..]) {
        Ok(dns_packet) => {
            // Look for domain in questions
            for question in dns_packet.questions {
                let domain = question.qname.to_string();
                if domain.ends_with("githubcopilot.com") {
                    let mut ips = Vec::new();

                    for answer in dns_packet.answers {
                        match answer.data {
                            dns_parser::RData::A(addr) => {
                                ips.push(IpAddr::V4(addr.0));
                            }
                            dns_parser::RData::AAAA(addr) => {
                                ips.push(IpAddr::V6(addr.0));
                            }
                            _ => {}
                        }
                    }

                    return Some((domain, ips));
                }
            }
            None
        }
        Err(_) => None,
    }
}

/// Gets the offset where DNS data starts in the packet
fn get_dns_offset(packet_data: &[u8]) -> Option<usize> {
    if packet_data.len() < 34 {
        // Minimum length for IPv4 + UDP headers
        return None;
    }

    // Skip Ethernet header (14 bytes)
    let ip_header_start = 14;

    // Get IP header length (IHL)
    let ip_header_len = (packet_data[ip_header_start] & 0x0F) * 4;

    // UDP header is 8 bytes
    let dns_start = ip_header_start + ip_header_len as usize + 8;

    if dns_start > packet_data.len() {
        None
    } else {
        Some(dns_start)
    }
}

fn skip_network_headers(packet_data: &[u8]) -> Option<&[u8]> {
    if packet_data.len() < 34 {
        return None;
    }

    // Ethernet header is 14 bytes
    let eth_header_len = 14;
    let ip_header_start = eth_header_len;
    let ip_header = &packet_data[ip_header_start..];

    if ip_header.len() < 20 {
        return None;
    }

    // IP header length is determined by the IHL field (lower 4 bits of the first byte)
    let ihl = ip_header[0] & 0x0F;
    let ip_header_len = (ihl * 4) as usize;

    if ip_header_len < 20 {
        return None;
    }

    let tcp_header_start = ip_header_start + ip_header_len;

    if packet_data.len() < tcp_header_start + 20 {
        return None;
    }

    let tcp_header = &packet_data[tcp_header_start..];

    // TCP header length is determined by the Data Offset field (upper 4 bits of the 13th byte)
    let data_offset = (tcp_header[12] >> 4) & 0x0F;
    let tcp_header_len = (data_offset * 4) as usize;

    if tcp_header_len < 20 {
        return None;
    }

    let payload_start = tcp_header_start + tcp_header_len;

    if payload_start >= packet_data.len() {
        None
    } else {
        Some(&packet_data[payload_start..])
    }
}

fn increment_counter(counts: &Arc<Mutex<HashMap<String, usize>>>, key: String) -> Result<()> {
    counts
        .lock()
        .map_err(|e| anyhow::anyhow!("failed to acquire lock: {}", e))?
        .entry(key)
        .and_modify(|c| *c += 1)
        .or_insert(1);
    Ok(())
}

fn print_lookup_table(lookup_counts: &Arc<Mutex<HashMap<String, usize>>>) {
    let counts = lookup_counts.lock().unwrap();
    let domain_width = counts
        .keys()
        .map(|s| s.len())
        .max()
        .unwrap_or(0)
        .max("Domain".len());

    println!(
        "{:<width$} | {:<5}",
        "Domain",
        "Count",
        width = domain_width
    );
    println!("{:-<width$}-+-{:-<5}", "", "", width = domain_width);
    for (domain, count) in counts.iter() {
        println!("{:<width$} | {:<5}", domain, count, width = domain_width);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_mock_dns_packet(domain: &str, response_ips: Vec<Ipv4Addr>) -> Vec<u8> {
        // Ethernet header (14 bytes)
        let mut packet = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
            0x08, 0x00, // EtherType (IPv4)
        ];

        // IPv4 header (20 bytes)
        packet.extend_from_slice(&[
            0x45, 0x00, // Version, IHL, DSCP, ECN
            0x00, 0x00, // Total Length
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags, Fragment Offset
            0x40, 0x11, // TTL, Protocol (UDP)
            0x00, 0x00, // Header Checksum
            192, 168, 1, 1, // Source IP
            8, 8, 8, 8, // Destination IP
        ]);

        // UDP header (8 bytes)
        packet.extend_from_slice(&[
            0x00, 0x35, // Source Port (53)
            0x00, 0x35, // Destination Port (53)
            0x00, 0x00, // Length
            0x00, 0x00, // Checksum
        ]);

        // DNS header (12 bytes)
        packet.extend_from_slice(&[
            0x00, 0x01, // Transaction ID
            0x81, 0x80, // Flags (Standard query response)
            0x00, 0x01, // Questions
            0x00, 0x01, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
        ]);

        // DNS question
        for part in domain.split('.') {
            packet.push(part.len() as u8);
            packet.extend_from_slice(part.as_bytes());
        }
        packet.push(0x00); // Root label

        // Type A, Class IN
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        // DNS answer
        for ip in response_ips {
            // Name pointer to question
            packet.extend_from_slice(&[0xc0, 0x0c]);
            // Type A, Class IN, TTL 300, Length 4
            packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
            packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]);
            packet.extend_from_slice(&[0x00, 0x04]);
            packet.extend_from_slice(&ip.octets());
        }

        packet
    }

    fn create_mock_tcp_packet(dest_ip: Ipv4Addr, dest_port: u16) -> Vec<u8> {
        // Ethernet header (14 bytes)
        let mut packet = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
            0x08, 0x00, // EtherType (IPv4)
        ];

        // IPv4 header (20 bytes)
        packet.extend_from_slice(&[
            0x45, 0x00, // Version, IHL, DSCP, ECN
            0x00, 0x28, // Total Length
            0x00, 0x00, // Identification
            0x00, 0x00, // Flags, Fragment Offset
            0x40, 0x06, // TTL, Protocol (TCP)
            0x00, 0x00, // Header Checksum
            192, 168, 1, 1, // Source IP
        ]);
        packet.extend_from_slice(&dest_ip.octets()); // Destination IP

        // TCP header (20 bytes)
        packet.extend_from_slice(&[
            0x00, 0x50, // Source Port (80)
        ]);
        packet.extend_from_slice(&dest_port.to_be_bytes()); // Destination Port
        packet.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x00, // Sequence Number
            0x00, 0x00, 0x00, 0x00, // Acknowledgment Number
            0x50, 0x00, // Data Offset, Flags
            0x00, 0x00, // Window
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent Pointer
        ]);

        packet
    }

    #[test]
    fn test_extract_githubcopilot_domain() {
        let test_ip = Ipv4Addr::new(20, 20, 20, 20);
        let packet = create_mock_dns_packet("api.githubcopilot.com", vec![test_ip]);

        let (domain, ips) = extract_githubcopilot_domain(&packet).unwrap();
        assert_eq!(domain, "api.githubcopilot.com");
        assert_eq!(ips, vec![IpAddr::V4(test_ip)]);
    }

    #[test]
    fn test_extract_dest_ip() {
        let test_ip = Ipv4Addr::new(20, 20, 20, 20);
        let packet = create_mock_tcp_packet(test_ip, 443);

        let extracted_ip = extract_dest_ip(&packet).unwrap();
        assert_eq!(extracted_ip, IpAddr::V4(test_ip));
    }
}
