use std::fmt;

use crate::fingerprinter::{get_fingerprint, get_template};
use crate::packets::{management_frame::Dot11MgmtFrame, InformationElement, MAC};

#[derive(serde::Serialize, Debug, Clone)]
pub struct Dot11ProbeRequest {
    #[serde(skip_serializing)]
    pub management_frame: Dot11MgmtFrame,
    pub ra: MAC,
    pub da: MAC,
    pub ta: MAC,
    pub sa: MAC,
    pub bssid: MAC,
    pub ies: Vec<InformationElement>,
}

impl Dot11ProbeRequest {
    pub fn parse_from_management_frame(management_frame: Dot11MgmtFrame) -> Result<Self, String> {
        let packet = &management_frame.frame_body;

        if management_frame.frame_sub_type != 4 {
            return Err(
                "Tried to parse a packet as Probe Request, that is not a Probe Request!"
                    .to_string(),
            );
        }

        let ra = management_frame.addr1.clone();
        let da = ra.clone();
        let ta = management_frame.addr2.clone();
        let sa = ta.clone();
        let bssid = management_frame.addr3.clone();

        let mut i: usize = 0;
        let mut ies: Vec<InformationElement> = Vec::new();
        while (packet.len() as i32 - i as i32) > 3 {
            match InformationElement::parse(&packet[i..]) {
                Ok(ie) => {
                    // println!("i={i} | IE: {}, {}, {:?}", ie.id, ie.len, ie.value);
                    i += ie.len as usize + 2;
                    ies.push(ie);
                }
                Err(_) => break,
            }
        }

        Ok(Dot11ProbeRequest {
            management_frame,
            ra,
            da,
            ta,
            sa,
            bssid,
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
        let mut bytes = Vec::new();

        // Serialize InformationElement
        for ie in &self.ies {
            ie.as_bytes(&mut bytes);
        }

        self.management_frame.as_bytes(bytes)
    }

    pub fn get_fingerprint(&self, template: Option<String>) -> String {
        get_fingerprint(self, template)
    }

    pub fn get_template(&self) -> String {
        get_template(self)
    }
}

impl fmt::Display for Dot11ProbeRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Dot11ProbeRequest: {:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_ie() {
        let packet = [
            0x00, 0x00, 0x10, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x09, 0x80, 0x00,
            0xe7, 0x9d, 0x40, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x26, 0xd1,
            0x3d, 0xb2, 0xad, 0x92, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x32, 0x00, 0x00,
            0x01, 0x04, 0x82, 0x84, 0x8b, 0x96, 0x32, 0x08, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48,
            0x60, 0x6c, 0x03, 0x01, 0x01, 0x2d, 0x1a, 0x2d, 0x40, 0x1b, 0xff, 0xff, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x0b, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x00,
            0x40, 0x00, 0x00, 0x20, 0xff, 0x1c, 0x23, 0x01, 0x08, 0x08, 0x18, 0x00, 0x80, 0x20,
            0x30, 0x02, 0x00, 0x0d, 0x00, 0x9f, 0x08, 0x00, 0x00, 0x00, 0xf5, 0xff, 0xf5, 0xff,
            0x39, 0x1c, 0xc7, 0x71, 0x1c, 0x07,
        ];
        match Dot11ProbeRequest::parse(&packet) {
            Ok(probe) => {
                assert_eq!(
                    probe.as_bytes(),
                    packet.to_vec(),
                    "Probe as bytes does not equal original packet!"
                );
            }
            Err(e) => {
                panic!("Unable to parse Dot11ProbeRequest! ({})", e);
            }
        }
    }
}
