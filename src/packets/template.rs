use std::fmt;

use crate::packets::InformationElement;

use crate::utils::bytes_to_hex;

#[derive(Debug, Clone)]
pub struct Dot11DataFrame {}

impl Dot11DataFrame {
    pub fn parse(packet: &[u8]) -> Result<Self, String> {
        Ok(Dot11DataFrame {})
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes
    }
}

impl fmt::Display for Dot11BeaconFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Dot11DataFrame: {:?}", self)
    }
}
