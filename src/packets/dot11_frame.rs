use std::fmt;

use super::{radio_tap_header::RadioTapHeaderFieldValue, RadioTapHeader, MAC};
use crate::{utils::bytes_to_hex_with_sep, MultiOption};

// #[repr(u8)]
// #[derive(Debug, Clone)]
// enum Dot11FrameType {
//     Management(Dot11MgmtFrame),
//     Control,
//     Data(Dot11DataFrame),
//     Extension,
// }

#[derive(Debug, Clone, Copy)]
pub struct SequenceControllField {
    pub fragment_number: u8,
    pub sequence_number: u16,
}

impl SequenceControllField {
    pub fn as_bytes(&self) -> Vec<u8> {
        let out: [u8; 2] = [
            self.fragment_number + (self.sequence_number << 4) as u8,
            (self.sequence_number >> 4) as u8,
        ];
        out.to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct Dot11Frame {
    pub radiotap_header: RadioTapHeader,
    /// Frame Control (2)
    pub frame_control: [u8; 2],
    pub frame_version: u8,
    pub frame_type: u8,
    pub frame_sub_type: u8,
    pub flags: u8,

    /// Duration (2)
    pub duration: u16,

    /// Address 1 (6)
    /// "Address 1 field always identifies the intended receiver(s) of the frame" [802.11-2020 / p767]
    pub addr1: MAC,

    /// Address 2 (0 / 6)
    /// "Address 2 field, where present, always identifies the transmitter of the frame" [802.11-2020 / p767]
    pub addr2: Option<MAC>,

    /// Address 3 (0 / 6)
    pub addr3: Option<MAC>,

    /// Sequence Control (0/2)
    pub seq_control: Option<SequenceControllField>,

    /// Address 4 (0/6)
    pub addr4: Option<MAC>,

    /// QoS Control (0/2)
    pub qos_control: Option<[u8; 2]>,

    /// HT Control (0/4)
    pub ht_control: Option<[u8; 4]>,

    /// Frame Body (XXX)
    pub frame_body: Vec<u8>,

    /// Frame Check Sum (4)
    pub fcs: Option<[u8; 4]>,
}

impl Dot11Frame {
    pub const EMPTY: Self = Self {
        radiotap_header: RadioTapHeader {
            pcap_packet_header: None,
            timetamp: None,
            it_version: 0,
            it_pad: 0,
            it_len: 8, // Minimum length for a valid radiotap header
            header_blocks: Vec::new(),
            content: Vec::new(),
        },
        frame_control: [0; 2],
        frame_version: 0,
        frame_type: 0,
        frame_sub_type: 0,
        flags: 0,
        duration: 0,
        addr1: MAC::BROADCAST,
        addr2: None,
        addr3: None,
        seq_control: None,
        addr4: None,
        qos_control: None,
        ht_control: None,
        frame_body: Vec::new(),
        fcs: None,
    };

    pub fn parse_from_radio_tap_header(radiotap_header: RadioTapHeader) -> Result<Self, String> {
        let packet = &radiotap_header.content;

        let frame_control: [u8; 2] = packet[0..2].try_into().unwrap();
        let frame_control_field = packet[0];
        let frame_version: u8 = frame_control_field & 0x3;
        let frame_type: u8 = frame_control_field >> 2 & 0x3;
        let frame_sub_type: u8 = frame_control_field >> 4 & 0xf;

        let htc: bool = (packet[1] >> 7 & 0x1) == 1;

        if htc {
            let msg = "HTC is set in Frame Header - unsupported!";
            // tracing::error!(msg);
            return Err(msg.to_string());
        }

        // parsing for control frames
        if frame_type == 1 {
            match frame_sub_type {
                0xB => {
                    // RTS
                    let flags = packet[1];
                    let duration = u16::from_le_bytes(packet[2..4].try_into().unwrap());
                    let addr1: MAC = packet[4..10].try_into().unwrap();
                    let addr2: MAC = packet[10..16].try_into().unwrap();
                    let mut content = packet[16..].to_vec();
                    let mut fcs = None;
                    if let MultiOption::One(MultiOption::One(RadioTapHeaderFieldValue::U8(value))) =
                        radiotap_header.get_header_flag_value(super::RadioTapHeaderFlag::Flags)
                    {
                        if value & 0x10 == 0x10 {
                            content = packet[16..packet.len() - 4].to_vec();
                            fcs = Some(packet[packet.len() - 4..].try_into().unwrap());
                        }
                    }
                    return Ok(Dot11Frame {
                        radiotap_header,
                        frame_control,
                        frame_version,
                        frame_type,
                        frame_sub_type,
                        flags,
                        duration,
                        addr1,
                        addr2: Some(addr2),
                        addr3: None,
                        seq_control: None,
                        addr4: None,
                        qos_control: None,
                        ht_control: None,
                        frame_body: content,
                        fcs,
                    });
                }
                0xC => {
                    // CTS
                    let flags = packet[1];
                    let duration = u16::from_le_bytes(packet[2..4].try_into().unwrap());
                    let addr1: MAC = packet[4..10].try_into().unwrap();
                    let mut content = packet[10..].to_vec();
                    let mut fcs = None;
                    if let MultiOption::One(MultiOption::One(RadioTapHeaderFieldValue::U8(value))) =
                        radiotap_header.get_header_flag_value(super::RadioTapHeaderFlag::Flags)
                    {
                        if value & 0x10 == 0x10 {
                            content = packet[10..packet.len() - 4].to_vec();
                            fcs = Some(packet[packet.len() - 4..].try_into().unwrap());
                        }
                    }
                    return Ok(Dot11Frame {
                        radiotap_header,
                        frame_control,
                        frame_version,
                        frame_type,
                        frame_sub_type,
                        flags,
                        duration,
                        addr1,
                        addr2: None,
                        addr3: None,
                        seq_control: None,
                        addr4: None,
                        qos_control: None,
                        ht_control: None,
                        frame_body: content,
                        fcs,
                    });
                }
                0xD => {
                    // ACK
                    let flags = packet[1];
                    let duration = u16::from_le_bytes(packet[2..4].try_into().unwrap());
                    let addr1: MAC = packet[4..10].try_into().unwrap();
                    let mut content = packet[10..].to_vec();
                    let mut fcs = None;
                    if let MultiOption::One(MultiOption::One(RadioTapHeaderFieldValue::U8(value))) =
                        radiotap_header.get_header_flag_value(super::RadioTapHeaderFlag::Flags)
                    {
                        if value & 0x10 == 0x10 {
                            content = packet[10..packet.len() - 4].to_vec();
                            fcs = Some(packet[packet.len() - 4..].try_into().unwrap());
                        }
                    }
                    return Ok(Dot11Frame {
                        radiotap_header,
                        frame_control,
                        frame_version,
                        frame_type,
                        frame_sub_type,
                        flags,
                        duration,
                        addr1,
                        addr2: None,
                        addr3: None,
                        seq_control: None,
                        addr4: None,
                        qos_control: None,
                        ht_control: None,
                        frame_body: content,
                        fcs,
                    });
                }
                _ => {}
            }
        }

        // parsing for management frames
        if (frame_type == 0 && frame_sub_type == 4) || (frame_type == 0 && frame_sub_type == 8) {
            let flags: u8 = packet[1];

            let duration: u16 = match packet[2..4].try_into() {
                Ok(d) => u16::from_le_bytes(d),
                Err(_) => 0,
            };

            let addr1: MAC = packet[4..10].try_into().unwrap();
            let addr2: MAC = packet[10..16].try_into().unwrap();
            let addr3: MAC = packet[16..22].try_into().unwrap();

            let seq_control: [u8; 2] = packet[22..24].try_into().unwrap();
            let seq_control = SequenceControllField {
                fragment_number: seq_control[0] & 0xf,
                sequence_number: u16::from_le_bytes(seq_control) >> 4,
            };
            // let addr4: MAC = [0; 6];

            let mut frame_body = packet[24..]
                .try_into()
                .expect("Dot11Frame - Could not unpack frame body");
            let mut fcs = None;

            if let MultiOption::One(MultiOption::One(RadioTapHeaderFieldValue::U8(value))) =
                radiotap_header.get_header_flag_value(super::RadioTapHeaderFlag::Flags)
            {
                if value & 0x10 == 0x10 {
                    frame_body = packet[24..packet.len() - 4]
                        .try_into()
                        .expect("Dot11Frame - Could not unpack frame body");
                    fcs = Some(
                        packet[packet.len() - 4..packet.len()]
                            .try_into()
                            .expect("Dot11Frame - Could not unpack Frame Check Sum!"),
                    );
                }
            }

            Ok(Dot11Frame {
                radiotap_header,
                frame_control,
                frame_version,
                frame_type,
                frame_sub_type,
                flags,
                duration,
                addr1,
                addr2: Some(addr2),
                addr3: Some(addr3),
                seq_control: Some(seq_control),
                addr4: None,
                qos_control: None,
                ht_control: None,
                frame_body,
                fcs,
            })
        } else if frame_type == 2 {
            let flags: u8 = packet[1];
            let duration: u16 = u16::from_le_bytes(packet[2..4].try_into().unwrap());

            let addr1: MAC = packet[4..10].try_into().unwrap();
            let addr2: MAC = packet[10..16].try_into().unwrap();
            let addr3: MAC = packet[16..22].try_into().unwrap();

            let seq_bytes: [u8; 2] = packet[22..24].try_into().unwrap();
            let seq_control = SequenceControllField {
                fragment_number: seq_bytes[0] & 0xf,
                sequence_number: u16::from_le_bytes(seq_bytes) >> 4,
            };

            let mut frame_body = packet[24..].to_vec();
            let mut fcs = None;
            if let MultiOption::One(MultiOption::One(RadioTapHeaderFieldValue::U8(value))) =
                radiotap_header.get_header_flag_value(super::RadioTapHeaderFlag::Flags)
            {
                if value & 0x10 == 0x10 {
                    frame_body = packet[24..packet.len() - 4].to_vec();
                    fcs = Some(packet[packet.len() - 4..].try_into().unwrap());
                }
            }

            return Ok(Dot11Frame {
                radiotap_header,
                frame_control,
                frame_version,
                frame_type,
                frame_sub_type,
                flags,
                duration,
                addr1,
                addr2: Some(addr2),
                addr3: Some(addr3),
                seq_control: Some(seq_control),
                addr4: None,
                qos_control: None,
                ht_control: None,
                frame_body,
                fcs,
            });
        } else {
            Err("Unsupported Frame Type!".to_string())
        }
    }

    pub fn parse(packet: &[u8]) -> Result<Self, String> {
        let radiotap_header =
            RadioTapHeader::parse(packet).expect("Unable to parse RadioTap Header!");
        Self::parse_from_radio_tap_header(radiotap_header)
    }

    pub fn as_bytes(&self, mut content: Vec<u8>) -> Vec<u8> {
        if let MultiOption::One(flags_option) = self
            .radiotap_header
            .get_header_flag_value(super::RadioTapHeaderFlag::Flags)
        {
            if let MultiOption::One(flags) = flags_option {
                if let RadioTapHeaderFieldValue::U8(value) = flags {
                    if value & 0x10 == 0x10 {
                        if let Some(fcs) = self.fcs {
                            content.extend_from_slice(&fcs);
                            // tracing::debug!("Dot11 Frame | with FrameCheckSum");
                        } else {
                            // tracing::warn!(
                            //     "Tried to export FCS, as RTH says its present - but it is None!"
                            // );
                        }
                    }
                }
            }
        }

        // tracing::debug!(
        //     "Dot11 Frame | content ({}): {}",
        //     content.len(),
        //     bytes_to_hex_with_sep(&content, ' ')
        // );

        self.radiotap_header.as_bytes(content)
    }
}

impl fmt::Display for Dot11Frame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Dot11Frame: {:?}", self)
    }
}
