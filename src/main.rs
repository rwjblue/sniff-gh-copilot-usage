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
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

pub struct Monitor {
    lookup_counts: Arc<Mutex<HashMap<String, usize>>>,
    ip_to_domain: Arc<Mutex<HashMap<IpAddr, String>>>,
    running: Arc<AtomicBool>,
    packet_capturer: Box<dyn PacketCapturer>,
}

// Trait for packet capture to allow mocking
pub trait PacketCapturer: Send {
    fn capture_next(&mut self) -> Result<Option<CapturedPacket>>;
}

// Struct to represent a captured packet
#[derive(Clone)]
pub struct CapturedPacket {
    pub data: Vec<u8>,
}

// Real implementation of PacketCapturer
struct PcapCapturer {
    capture: Capture<pcap::Active>,
}

impl PacketCapturer for PcapCapturer {
    fn capture_next(&mut self) -> Result<Option<CapturedPacket>> {
        match self.capture.next_packet() {
            Ok(packet) => Ok(Some(CapturedPacket {
                data: packet.data.to_vec(),
            })),
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Packet capture error: {}", e)),
        }
    }
}

impl Monitor {
    pub fn new(
        packet_capturer: Box<dyn PacketCapturer>,
        initial_domains: Vec<&str>,
    ) -> Result<Self> {
        Ok(Self {
            lookup_counts: Arc::new(Mutex::new(HashMap::new())),
            ip_to_domain: Arc::new(Mutex::new(get_initial_ip_to_domain_mapping(
                initial_domains,
            )?)),
            running: Arc::new(AtomicBool::new(true)),
            packet_capturer,
        })
    }

    pub fn start_capture_thread(mut self) -> Result<MonitorHandle> {
        let running = Arc::clone(&self.running);
        let lookup_counts = Arc::clone(&self.lookup_counts);

        let (error_tx, error_rx) = std::sync::mpsc::channel();

        let capture_thread = thread::spawn(move || -> Result<()> {
            while self.running.load(Ordering::Relaxed) {
                match self.packet_capturer.capture_next() {
                    Ok(Some(packet)) => {
                        if let Err(e) = self.process_packet(&packet) {
                            error!("Error processing packet: {}", e);
                            error_tx.send(e).ok();
                            break;
                        }
                    }
                    Ok(None) => continue, // Timeout, try again
                    Err(e) => {
                        error_tx.send(e).ok();
                        break;
                    }
                }
            }
            Ok(())
        });

        Ok(MonitorHandle {
            running,
            capture_thread: Some(capture_thread),
            error_rx,
            lookup_counts,
        })
    }

    fn process_packet(&self, packet: &CapturedPacket) -> Result<()> {
        if let Some((domain, ips)) = extract_githubcopilot_domain(&packet.data) {
            self.increment_counter(domain.clone())?;

            let mut ip_map = self
                .ip_to_domain
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire ip_to_domain lock: {}", e))?;
            for ip in ips {
                ip_map.insert(ip, domain.clone());
            }
        }

        if let Ok(dest_ip) = extract_dest_ip(&packet.data) {
            let ip_map = self
                .ip_to_domain
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to acquire ip_to_domain lock: {}", e))?;
            if let Some(domain) = ip_map.get(&dest_ip) {
                self.increment_counter(domain.clone())?;
            }
        }

        Ok(())
    }

    fn increment_counter(&self, domain: String) -> Result<()> {
        self.lookup_counts
            .lock()
            .map_err(|e| anyhow::anyhow!("failed to acquire lock: {}", e))?
            .entry(domain)
            .and_modify(|c| *c += 1)
            .or_insert(1);

        Ok(())
    }
}

pub struct MonitorHandle {
    running: Arc<AtomicBool>,
    capture_thread: Option<thread::JoinHandle<Result<()>>>,
    error_rx: std::sync::mpsc::Receiver<anyhow::Error>,
    lookup_counts: Arc<Mutex<HashMap<String, usize>>>,
}

impl MonitorHandle {
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn wait(mut self) -> Result<HashMap<String, usize>> {
        while self.running.load(Ordering::Relaxed) {
            if let Ok(error) = self.error_rx.try_recv() {
                error!(error = %error, "received capture error");
                self.stop();
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        if let Some(thread) = self.capture_thread.take() {
            thread
                .join()
                .map_err(|e| anyhow::anyhow!("Capture thread panicked: {:?}", e))??;
        }

        Ok(self
            .lookup_counts
            .lock()
            .map_err(|e| anyhow::anyhow!("Failed to acquire counts lock: {}", e))?
            .clone())
    }

    pub fn get_counts(&self) -> Result<HashMap<String, usize>> {
        Ok(self
            .lookup_counts
            .lock()
            .map_err(|e| anyhow::anyhow!("Failed to acquire lock: {}", e))?
            .clone())
    }
}

#[derive(Parser, Debug)]
#[command(about = "Monitor usage of domains ending in githubcopilot.com")]
struct Cli {
    /// Network interface to listen on
    #[arg(short, long)]
    interface: Option<String>,
}

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")),
        )
        .init();
}

fn get_interface_name(cli: &Cli) -> Result<String> {
    Ok(cli
        .interface
        .clone()
        .unwrap_or_else(|| {
            get_default_interface()
                .context("Failed to detect default interface")
                .unwrap_or_else(|e| {
                    eprintln!("Warning: {}, falling back to en0", e);
                    "en0".to_string()
                })
        })
        .to_string())
}

fn setup_ctrlc_handler(handle: &MonitorHandle) -> Result<()> {
    let running = Arc::clone(&handle.running);

    ctrlc::set_handler(move || {
        info!("Received Ctrl-C!");
        running.store(false, Ordering::Relaxed);
    })?;

    Ok(())
}

fn main() -> Result<()> {
    setup_logging();
    let cli = Cli::parse();

    let interface = get_interface_name(&cli)?;
    let capturer = create_packet_capturer(&interface)?;

    let domains = vec![
        "api.githubcopilot.com",
        "api.enterprise.githubcopilot.com",
        "api.individual.githubcopilot.com",
        "proxy.enterprise.githubcopilot.com",
        "proxy.individual.githubcopilot.com",
    ];

    let monitor = Monitor::new(capturer, domains)?;
    let handle = monitor.start_capture_thread()?;

    setup_ctrlc_handler(&handle)?;

    let final_counts = handle.wait()?;
    print_lookup_table(&final_counts);
    Ok(())
}

fn create_packet_capturer(interface: &str) -> Result<Box<dyn PacketCapturer>> {
    let device = Capture::from_device(interface)?;
    let mut capture = device
        .promisc(true)
        .timeout(100)
        .immediate_mode(true)
        .open()?;

    capture
        .filter("port 53 or port 80 or port 443", true)
        .context("setting capture filter")?;

    Ok(Box::new(PcapCapturer { capture }))
}

fn get_default_interface() -> Result<String> {
    Device::list()
        .map_err(|e| anyhow::anyhow!("failed to list devices: {}", e))?
        .into_iter()
        .next()
        .map(|dev| dev.name)
        .ok_or_else(|| anyhow::anyhow!("no capture devices found"))
}

fn get_initial_ip_to_domain_mapping(hostnames: Vec<&str>) -> Result<HashMap<IpAddr, String>> {
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

fn print_lookup_table(lookup_counts: &HashMap<String, usize>) {
    let domain_width = lookup_counts
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
    for (domain, count) in lookup_counts.iter() {
        println!("{:<width$} | {:<5}", domain, count, width = domain_width);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // Mock packet capturer for testing
    struct MockCapturer {
        packets: Vec<CapturedPacket>,
        current: usize,
    }

    impl PacketCapturer for MockCapturer {
        fn capture_next(&mut self) -> Result<Option<CapturedPacket>> {
            if self.current < self.packets.len() {
                let packet = self.packets[self.current].clone();
                self.current += 1;
                Ok(Some(packet))
            } else {
                Ok(None)
            }
        }
    }

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

    #[test]
    fn test_monitor_threaded_capture() -> Result<()> {
        let dns_packet =
            create_mock_dns_packet("api.githubcopilot.com", vec![Ipv4Addr::new(20, 20, 20, 20)]);

        let mock_capturer = MockCapturer {
            packets: vec![CapturedPacket { data: dns_packet }],
            current: 0,
        };

        let monitor = Monitor::new(Box::new(mock_capturer), vec!["api.githubcopilot.com"])?;

        let handle = monitor.start_capture_thread()?;

        // Give it a moment to process
        thread::sleep(Duration::from_millis(100));

        handle.stop();
        let counts = handle.wait()?;

        assert_eq!(counts.get("api.githubcopilot.com"), Some(&1));

        Ok(())
    }
}
