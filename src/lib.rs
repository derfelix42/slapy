mod sniffer;
use sniffer::Sniffer;

pub fn sniff(filename: String, callback: fn()) {
    let _sniffer = Sniffer::new(uuid::Uuid::new_v4());
    println!("Sniffing file {}", filename);
    callback();
}

pub fn test(test: String) {
    println!("Testing: {test}");
}
