use anyhow::{Context, Result};
use clap::Parser;
use pcap::Capture;
use signal_hook::consts::SIGINT;
use signal_hook::flag;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(about = "Monitor DNS lookups for domains ending in githubcopilot.com")]
struct Cli {
    /// Network interface to listen on
    #[arg(short, long, default_value = "any")]
    interface: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let lookup_counts = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
    let running = Arc::new(AtomicBool::new(true));
    flag::register(SIGINT, running.clone())?;

    let interface = cli.interface.clone();
    let lookup_counts_ref = Arc::clone(&lookup_counts);
    let running_ref = Arc::clone(&running);

    let (error_tx, error_rx) = std::sync::mpsc::channel();

    let capture_thread = thread::spawn(move || -> Result<()> {
        let mut capture = Capture::from_device(interface.as_str())
            .context("failed to open capture device")?
            .promisc(true)
            .open()
            .context("failed to start capture")?;

        while running_ref.load(Ordering::Relaxed) {
            match capture.next_packet() {
                Ok(packet) => {
                    if let Some(domain) = extract_githubcopilot_domain(packet.data) {
                        lookup_counts_ref
                            .lock()
                            .map_err(|e| anyhow::anyhow!("failed to acquire lock: {}", e))?
                            .entry(domain)
                            .and_modify(|c| *c += 1)
                            .or_insert(1);
                    }
                }
                Err(e) => {
                    error_tx
                        .send(anyhow::Error::new(e))
                        .context("failed to send error")?;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    });

    while running.load(Ordering::Relaxed) {
        if let Ok(error) = error_rx.try_recv() {
            eprintln!("Capture error: {:#}", error);
            running.store(false, Ordering::Relaxed);
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    running.store(false, Ordering::Relaxed);
    capture_thread
        .join()
        .map_err(|e| anyhow::anyhow!("capture thread panicked: {:?}", e))??;

    print_lookup_table(&lookup_counts);
    Ok(())
}

/// Extracts domain from a DNS packet if it matches `githubcopilot.com`
fn extract_githubcopilot_domain(packet_data: &[u8]) -> Option<String> {
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
                    return Some(domain);
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

/// Prints out the lookup table
fn print_lookup_table(lookup_counts: &Arc<Mutex<HashMap<String, usize>>>) {
    let counts = lookup_counts.lock().unwrap();
    println!("{:<30} | {:<5}", "Domain", "Count");
    println!("{:-<30}-+-{:-<5}", "", "");
    for (domain, count) in counts.iter() {
        println!("{:<30} | {:<5}", domain, count);
    }
}
