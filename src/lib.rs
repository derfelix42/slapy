mod packets;
mod sniffer;
mod utils;
use sniffer::Sniffer;

pub fn sniff(filename: String, callback: fn()) {
    let _sniffer = Sniffer::new(uuid::Uuid::new_v4());
    println!("Sniffing file {}", filename);
    callback();
}

pub fn test(test: String) {
    println!("Testing: {test}");
}

#[derive(Debug, Clone)]
pub enum MultiOption<T> {
    One(T),
    Multi(Vec<T>),
    None,
}

impl<T> MultiOption<T> {
    pub fn is_one(&self) -> bool {
        match self {
            MultiOption::One(_) => true,
            _ => false,
        }
    }

    pub fn is_multi(&self) -> bool {
        match self {
            MultiOption::Multi(_) => true,
            _ => false,
        }
    }

    pub fn is_none(&self) -> bool {
        match self {
            MultiOption::None => true,
            _ => false,
        }
    }
}
