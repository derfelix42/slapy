use std::error::Error;
use std::fmt;

use super::MAC;
use crate::packets::Dot11Frame;

#[derive(Debug, Clone)]
pub struct Dot11DataFrame {
    pub dot11frame: Dot11Frame,
    pub frame_version: u8,
    pub frame_type: u8,
    pub frame_sub_type: u8,
    pub flags: u8,
    pub duration: u16,
    pub addr1: MAC,
    pub addr2: MAC,
    pub addr3: MAC,
    pub seq_num: u16,
    pub frag_num: u8,
    pub frame_body: Vec<u8>,
}

impl Dot11DataFrame {
    pub fn parse(packet: &[u8]) -> Result<Self, String> {
        match Dot11Frame::parse(packet) {
            Ok(dot11frame) => Self::parse_from_dot11_frame(dot11frame),
            Err(e) => Err(format!("Unable to parse Dot11Frame: {e}")),
        }
    }

    pub fn parse_from_dot11_frame(dot11_frame: Dot11Frame) -> Result<Self, String> {
        Ok(Self {
            dot11frame: dot11_frame.clone(),
            addr1: dot11_frame.addr1.clone(),
            addr2: dot11_frame.addr2.unwrap(),
            frame_version: 0,
            frame_type: 0,
            frame_sub_type: 0,
            flags: 0,
            duration: 0,
            addr3: MAC::ERROR,
            seq_num: 0,
            frag_num: 0,
            frame_body: vec![],
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let bytes: Vec<u8> = Vec::new();

        bytes
    }
}

impl fmt::Display for Dot11DataFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Dot11DataFrame: {:?}", self)
    }
}
