//! Slapy
//!
//! A much faster alternative to Pythons Scapy Library.
//! Process PCAP files of captured Wi-Fi traffic.
fn main() {
    println!("This is slapy - a much faster scapy alternative!");
}

mod sniffer;
use sniffer::Sniffer;

pub fn sniff(filename: String, callback: fn()) {
    let _sniffer = Sniffer::new(uuid::Uuid::new_v4());
    println!("Sniffing file {}", filename);
    callback();
}
