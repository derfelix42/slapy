use std::fmt;

use crate::packets::management_frame::Dot11MgmtFrame;
use crate::packets::InformationElement;

#[derive(Debug, Clone)]
pub struct Dot11BeaconFrame {
    pub management_frame: Dot11MgmtFrame,
    pub timestamp: u64,
    pub beacon_interval: u16,
    pub capabilities: u16,
    pub ies: Vec<InformationElement>,
}

impl Dot11BeaconFrame {
    pub fn parse_from_management_frame(management_frame: Dot11MgmtFrame) -> Result<Self, String> {
        let packet = &management_frame.frame_body;

        if management_frame.frame_sub_type != 8 {
            return Err(
                "Tried to parse a packet as Beacon Frame, that is not a Beacon Frame!".to_string(),
            );
        }

        let i = 24;

        // Fixed Parameters
        let timestamp = match packet[i + 0..i + 8].try_into() {
            Ok(p) => {
                let x = u64::from_le_bytes(p);
                // tracing::info!("timestamp: {:?} -> {}", bytes_to_hex(&p), x);
                x
            }
            Err(e) => {
                tracing::info!("Failed to map bytes into timestamp_bytes: {}", e);
                0
            }
        };

        let beacon_interval = match packet[i + 8..i + 10].try_into() {
            Ok(p) => u16::from_le_bytes(p),
            Err(e) => {
                tracing::info!("Failed to map bytes into beacon_interval: {}", e);
                0
            }
        };

        let capabilities = match packet[i + 10..i + 12].try_into() {
            Ok(p) => u16::from_le_bytes(p),
            Err(e) => {
                tracing::info!("Failed to map bytes into capabilities: {}", e);
                0
            }
        };

        // Tagged Parameters (IEs)
        let mut i: usize = i + 12;
        let mut ies: Vec<InformationElement> = Vec::new();
        while (packet.len() as i32 - i as i32) as i32 > 3 {
            match InformationElement::parse(&packet[i..]) {
                Ok(ie) => {
                    i += ie.len as usize + 2;
                    // tracing::info!("IE {}, len:{} - {}", ie.id, ie.len, bytes_to_hex(&ie.value));
                    ies.push(ie);
                }
                Err(_) => break,
            }
        }

        Ok(Dot11BeaconFrame {
            management_frame,
            timestamp,
            beacon_interval,
            capabilities,
            ies,
        })
    }

    pub fn parse(packet: &[u8]) -> Result<Self, String> {
        match Dot11MgmtFrame::parse(packet) {
            Ok(management_frame) => Self::parse_from_management_frame(management_frame),
            Err(e) => Err(format!("Unable to parse Management Frame Header: {e}")),
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.beacon_interval.to_le_bytes());
        bytes.extend_from_slice(&self.capabilities.to_le_bytes());

        // Serialize InformationElement
        for ie in &self.ies {
            ie.as_bytes(&mut bytes);
        }

        self.management_frame.as_bytes(bytes)
    }
}

impl fmt::Display for Dot11BeaconFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Dot11BeaconFrame: {:?}", self)
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn bytes_to_ie() {
//         let packet = [
//             0x40, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x26, 0xd1, 0x3d, 0xb2,
//             0xad, 0x92, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x32, 0x00, 0x00, 0x01, 0x04,
//             0x82, 0x84, 0x8b, 0x96, 0x32, 0x08, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c,
//             0x03, 0x01, 0x01, 0x2d, 0x1a, 0x2d, 0x40, 0x1b, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
//             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//             0x00, 0x00, 0x00, 0x7f, 0x0b, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00,
//             0x00, 0x20, 0xff, 0x1c, 0x23, 0x01, 0x08, 0x08, 0x18, 0x00, 0x80, 0x20, 0x30, 0x02,
//             0x00, 0x0d, 0x00, 0x9f, 0x08, 0x00, 0x00, 0x00, 0xf5, 0xff, 0xf5, 0xff, 0x39, 0x1c,
//             0xc7, 0x71, 0x1c, 0x07,
//         ];
//         match Dot11ProbeRequest::parse(&packet) {
//             Ok(probe) => {
//                 assert_eq!(
//                     probe.as_bytes(),
//                     packet.to_vec(),
//                     "Probe as bytes does not equal original packet!"
//                 );
//             }
//             Err(e) => {
//                 panic!("Unable to parse Dot11ProbeRequest! ({})", e);
//             }
//         }
//     }
// }
