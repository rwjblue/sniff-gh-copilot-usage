use anyhow::{Context, Result};
use clap::Parser;
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::net::IpAddr;
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
#[command(about = "Monitor DNS lookups for domains ending in githubcopilot.com")]
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
    debug!(?cli, "starting DNS monitor");

    let lookup_counts = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
    let dns_results_ref = Arc::new(Mutex::new(HashMap::<String, Vec<IpAddr>>::new()));
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
        if let Err(e) = capture_packets(interface, lookup_counts_ref, dns_results_ref, running_ref)
        {
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

    info!("DNS monitor completed successfully");
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

fn capture_packets(
    interface: String,
    lookup_counts_ref: Arc<Mutex<HashMap<String, usize>>>,
    dns_results_ref: Arc<Mutex<HashMap<String, Vec<IpAddr>>>>,
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
        .filter("udp port 53", true)
        .context("setting capture filter")?;

    while running_ref.load(Ordering::Relaxed) {
        match capture.next_packet() {
            Ok(packet) => {
                if let Some((domain, ips)) = extract_githubcopilot_domain(packet.data) {
                    info!(domain = %domain, "detected GitHub Copilot DNS lookup");
                    lookup_counts_ref
                        .lock()
                        .map_err(|e| anyhow::anyhow!("failed to acquire lock: {}", e))?
                        .entry(domain.clone())
                        .and_modify(|c| *c += 1)
                        .or_insert(1);

                    if !ips.is_empty() {
                        dns_results_ref
                            .lock()
                            .map_err(|e| anyhow::anyhow!("failed to acquire lock: {}", e))?
                            .insert(domain.clone(), ips);

                        info!(domain = %domain, "recorded DNS resolution");
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
