use std::{i8, sync::Arc, time::Duration};

use crate::{packets::RadioTapHeaderFlag, utils::bytes_to_hex_with_sep, MultiOption};

use super::PcapPacketHeader;

/// Radio Tap Header
/// 
/// ``` c
/// struct ieee80211_radiotap_header {
///     u_int8_t        it_version;     /* set to 0 */
///     u_int8_t        it_pad;
///     u_int16_t       it_len;         /* entire length */
///     u_int32_t       it_present;     /* fields present */
/// } __attribute__((__packed__));
/// ```
#[derive(Debug, Clone)]
pub struct RadioTapHeaderBlock {
    flags: u32,
    fields: Vec<RadioTapHeaderField>
}

impl RadioTapHeaderBlock {
    pub fn get_flag_value(&self, field_type: RadioTapHeaderFlag) -> MultiOption<RadioTapHeaderFieldValue> {
        if &self.flags >> field_type as u8 & 0x1 == 0x1 {
            self.fields.iter().find(|x| x.id == field_type).unwrap().clone().val
        } else {
            MultiOption::None
        }

    }
}

#[derive(Debug, Clone)]
pub struct RadioTapHeaderField {
    pub id: RadioTapHeaderFlag,
    pub val: MultiOption<RadioTapHeaderFieldValue>
}

#[derive(Debug, Clone)]
pub enum RadioTapHeaderFieldValue {
    Bool(bool),
    U8(u8),
    I8(i8),
    U16(u16),
    U32(u32),
    Str(String),
    Raw(Vec<u8>)
}

impl RadioTapHeaderFieldValue {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            RadioTapHeaderFieldValue::Bool(val) => [*val as u8].to_vec(),
            RadioTapHeaderFieldValue::U8(val) => [*val].to_vec(),
            RadioTapHeaderFieldValue::I8(val) => [*val as u8].to_vec(),
            RadioTapHeaderFieldValue::U16(val) => val.to_le_bytes().to_vec(),
            RadioTapHeaderFieldValue::U32(val) => val.to_le_bytes().to_vec(),
            RadioTapHeaderFieldValue::Str(val) => val.as_bytes().to_vec(),
            RadioTapHeaderFieldValue::Raw(val) => val.clone(),
            // _ => Vec::new()
        }
    }
}

fn check_bit(flags: &u32, bit: u8) -> bool {
    ((flags >> bit) & 0x1) == 1
}

#[derive(Debug, Clone)]
pub struct AntennaInfo {
    pub antenna_num: u8,
    pub antenna_signal: i8,
    pub antenna_noise: i8,
}

#[derive(Debug, Clone)]
pub struct RadioTapHeader {
    pub pcap_packet_header: Option<Arc<PcapPacketHeader>>,
    pub timetamp: Option<Duration>,
    pub it_version: u8,
    pub it_pad: u8,
    pub it_len: u16,
    pub header_blocks: Vec<RadioTapHeaderBlock>,
    pub content: Vec<u8>,
}

impl RadioTapHeader {
    pub fn parse_from_pcap_packet_header(packet: PcapPacketHeader) -> Result<Self, String> {
        let mut rt_header = match Self::parse(&packet.data) {
            Ok(mut rt_header) => {
                rt_header.timetamp = Some(packet.timestamp);
                rt_header
            }
            Err(e) => return Err(e)
        };

        rt_header.add_pcap_packet_header(packet);
        Ok(rt_header)
    }

    pub fn add_pcap_packet_header(&mut self, header: PcapPacketHeader) {
        self.pcap_packet_header = Some(Arc::new(header));
    }

    pub fn parse(packet: &[u8]) -> Result<Self, String> {
        // tracing::debug!("got packet for parsing: {}", bytes_to_hex_with_sep(packet, ' '));

        // Verify that at least the minimal length of the header is present
        if packet.len() < 8 {
            return Err("Packet is too short to contain a valid RadioTap header".into());
        }

        let version = packet[0];
        let pad = packet[1];

        // Read the length as a u16 (big-endian)
        let header_length: u16 = u16::from_le_bytes(packet[2..4].try_into().expect("Could not read bytes"));

        // tracing::debug!("Version: {version}, pad: {pad}, header length: {header_length}");

        // RadioTapHeader can have multiple flag fields
        // https://www.radiotap.org/#extended-presence-masks
        let mut header_blocks = Vec::new();
        let mut i: usize = 4;
        
        loop {
            // Read flags as a u32 (big-endian) and init fields
            let block = RadioTapHeaderBlock {
                flags: u32::from_le_bytes(packet[i..i+4].try_into().expect("Could not read bytes")),
                fields: Vec::new()
            };

            let next_block = (block.flags >> 31 & 0x1) == 1;

            header_blocks.push(block);

            i += 4;

            if !next_block {
                break;
            }

        }

        // tracing::debug!("Got {} header blocks", header_blocks.len());

        // Ensure the packet is long enough for the content section
        if packet.len() < header_length as usize {
            let msg = format!("Packet is too short for the specified content length. Expected at least {} - got {}", 
                header_length, 
                packet.len()
            );
            // tracing::debug!(msg);
            return Err(msg);
        }

        // Fields defined as in https://www.radiotap.org/fields/defined
        // For even more info, look into: https://github.com/radiotap/radiotap-library/blob/master/radiotap.h (or somehow embed this here?)
        for blocks in &header_blocks {
            // tracing::debug!("RadioTapHeader - flags: {}", bytes_to_hex_with_sep(&blocks.flags.to_le_bytes().to_vec(), ' '));
        }
        // tracing::debug!("RadioTapHeader - length: {}", header_length);
        // tracing::debug!("RadioTapHeader - fields: {}", bytes_to_hex_with_sep(&packet[i..header_length as usize], ' '));

        for block in &mut header_blocks {
            let flags = &block.flags;
            for bit in 0u8..31 {
                if check_bit(flags, bit) {
                    // tracing::debug!("Checking bit {bit}");
                    let flag = RadioTapHeaderFlag::try_from(bit as usize).unwrap();
                    if flag.required_padding() != 0 {
                        let padding = i % flag.required_padding();
                        i += padding;
                    }
                    let value: Vec<u8> = packet[i..i+flag.num_bytes()].try_into().unwrap();
                    match bit {
                        1 => { // Flags
                            // Frame Check Sum is `value[0] & 0x10 == 0x10`
                            block.fields.push(RadioTapHeaderField { id: flag, val: MultiOption::One(RadioTapHeaderFieldValue::U8(value[0])) });
                        }
    
                        2 => { // channel rate
                            block.fields.push(RadioTapHeaderField { id: flag, val: MultiOption::One(RadioTapHeaderFieldValue::U8(value[0])) });
                        }
    
                        3 => { // channel requency, flags, channel num
                            let freq = u16::from_le_bytes(value[0..2].try_into().unwrap());

                            block.fields.push(RadioTapHeaderField { id: flag, val: MultiOption::Multi(vec![
                                RadioTapHeaderFieldValue::U16(freq),
                                RadioTapHeaderFieldValue::U16(u16::from_le_bytes(value[2..4].try_into().unwrap())),
                                // RadioTapHeaderFieldValue::U16(get_channel_number(freq as u32) as u16),
                            ]) });
                        }
                        
                        5 => { // Antenna signal
                            block.fields.push(RadioTapHeaderField { id: flag, val: MultiOption::One(RadioTapHeaderFieldValue::I8(value[0] as i8)) });
                        }
                        
                        6 => { // Antenna noise
                            block.fields.push(RadioTapHeaderField { id: flag, val: MultiOption::One(RadioTapHeaderFieldValue::I8(value[0] as i8)) });
                        }
    
                        11 => { // Antenna
                            block.fields.push(RadioTapHeaderField { id: flag, val: MultiOption::One(RadioTapHeaderFieldValue::U8(value[0])) });
                        }

                        30 => {
                            // tracing::error!("Vendor specific Namespace in flags field! Not yet implemented! Probably leads to unintenden behaviour!!!");
                        }
                        
                        _ => {
                            block.fields.push(RadioTapHeaderField { id: flag, val: MultiOption::One(RadioTapHeaderFieldValue::Raw(value.clone())) });
                        }
                    }
                    
                    // tracing::debug!("Bit {bit} ({}) is set with value {}!",flag.name(), bytes_to_hex_with_sep(&value, ' '));
    
                    i += flag.num_bytes();
                }
            }
        }

        // Extract the content section
        let content = packet[header_length as usize..packet.len()].to_vec();

        // Create and return the RadioTapHeader
        Ok(RadioTapHeader {
            pcap_packet_header: None,
            timetamp: None,
            it_version: version,
            it_pad: pad,
            it_len: header_length,
            header_blocks,
            content,
        })
    }

    pub fn as_bytes(&self, packet: Vec<u8>) -> Vec<u8> {
        // tracing::debug!("getting called to return bytes");

        let mut flags = Vec::new();        
        for i in 0..self.header_blocks.len() {
            let block = &self.header_blocks[i];
            let mut flags_val: u32 = block.flags;
            if i < self.header_blocks.len()-1 && flags_val >> 24 & 0xa0 == 0 {
                flags_val += 0xa0 << 24;
            }
            flags.extend_from_slice(&flags_val.to_le_bytes());            
        }

        let mut data = Vec::new();
        for block in &self.header_blocks {
            let mut sorted_fields = block.fields.clone();
            sorted_fields.sort_by(|a,b| (a.id as u8).cmp(&(b.id as u8)));
            for field in sorted_fields {
                if field.id == RadioTapHeaderFlag::RadiotapNamespaceNext {
                    continue;
                }

                let padding = if field.id.required_padding() != 0 {
                    (4 + flags.len() + data.len()) % field.id.required_padding()
                } else {
                    0
                };
                
                match field.val {
                    MultiOption::One(val) => {
                        data.extend_from_slice(vec![0;padding].as_slice());
                        data.extend_from_slice(&val.to_bytes());
                        // tracing::debug!("Flag {}, length {}, padding {padding} ({}): {:?} -> {}", (field.id as u8), field.id.num_bytes(), field.id.name(), val, bytes_to_hex_with_sep(&val.to_bytes(), ' '));
                    }
                    
                    MultiOption::Multi(vals) => {
                        data.extend_from_slice(vec![0;padding].as_slice());
                        for val in vals {
                            data.extend_from_slice(&val.to_bytes());
                            // tracing::debug!("Flag {}, length {}, padding {padding} ({}): {:?} -> {}", (field.id as u8), field.id.num_bytes(), field.id.name(), val,bytes_to_hex_with_sep(&val.to_bytes(), ' '));
                        }
                        
                    }
                    
                    _ => {}
                }
            }            
        }

        let mut bytes = Vec::new();

        // minimum radio tap header
        bytes.push(self.it_version);
        bytes.push(self.it_pad);
        
        // set new length and flags for radio tap header
        let new_len: u16 = (4 + flags.len() + data.len()) as u16;
        bytes.extend_from_slice(&new_len.to_le_bytes());

        // add flags
        bytes.extend_from_slice(&flags);

        // add actual values
        bytes.extend_from_slice(&data);

                
        // Add packet content
        bytes.extend_from_slice(&packet);
        
        // tracing::debug!("Radiotap Header | flags: {}, len: {}, values: {}", bytes_to_hex_with_sep(&flags, ' '), new_len,  bytes_to_hex_with_sep(&data, ' '));
        // tracing::debug!("Radiotap Header | packet ({}): {}", bytes.len(), bytes_to_hex_with_sep(&bytes, ' '));
        
        bytes
    }

    pub fn get_header_flag_value(&self, field_type: RadioTapHeaderFlag) -> MultiOption<MultiOption<RadioTapHeaderFieldValue>> {
        let mut values = Vec::new();

        for block in &self.header_blocks {
            if block.flags >> field_type as u8 & 0x1 == 0x1 {
                values.push(block.fields.iter().find(|x| x.id == field_type).unwrap().clone().val);
            }
        }

        match values.len() {
            0 => MultiOption::None,
            1 => MultiOption::One(values[0].clone()),
            _ => MultiOption::Multi(values)
        }        
    }

    pub fn update_first_header_flag_value(&self, field_type: RadioTapHeaderFlag, field_value: RadioTapHeaderField) -> Self {
        // Create a mutable clone of self
        let mut new_self = self.clone();
        let block = &mut new_self.header_blocks[0];

        // Check if block contains field to be replaced
        if block.flags >> field_type as u8 & 0x1 == 0x1 {
            // Remove the old field value
            block.fields.retain(|f| f.id != field_type);

            // Insert new field value
            block.fields.push(field_value);
        } else {
            // Field not present, update flags and insert new field value
            block.flags |= 1 << field_type as u8;
            block.fields.push(field_value);
        }

        new_self
    }

    pub fn add_sniffer_measurement(&mut self, packet: &RadioTapHeader) -> Self {
        // tracing::debug!("Adding sniffer measurement");
        let mut new_header_block= RadioTapHeaderBlock {
            flags: 0,
            fields: Vec::new()
        };
        
        // Channel Information
        let flag = RadioTapHeaderFlag::Channel;
        let channel = match packet.get_header_flag_value(RadioTapHeaderFlag::Channel) {
            MultiOption::One(channel) => Some(channel),
            MultiOption::Multi(channels) => Some(channels[0].clone()),
            _ => None,
        };
        let channel = if let Some(channel) = channel {
            match channel {
                // MultiOption::One(channel) => Some(channel),
                MultiOption::Multi(channel) => Some(channel.clone()),
                _ => None
            }
        } else {
            None
        };

        if let Some(channel) = channel {
            // tracing::debug!("channel: {:?}", channel);

            new_header_block.flags += 0x1 << flag as u8;
            new_header_block.fields.push(RadioTapHeaderField {
                id: flag,
                val: MultiOption::Multi(channel)
            });
        }


        // Antenna Signal
        let flag = RadioTapHeaderFlag::AntennaSignal;
        let signal = match packet.get_header_flag_value(RadioTapHeaderFlag::AntennaSignal) {
            MultiOption::One(signal) => Some(signal),
            MultiOption::Multi(signals) => Some(signals[0].clone()),
            _ => None,
        };
        let signal = if let Some(signal) = signal {
            match signal {
                MultiOption::One(signal) => Some(signal),
                MultiOption::Multi(signal) => Some(signal[0].clone()),
                _ => None
            }
        } else {
            None
        };

        if let Some(signal) = signal {
            // tracing::debug!("signal: {:?}", signal);
            new_header_block.flags += 0x1 << flag as u8;
            new_header_block.fields.push(RadioTapHeaderField {
                id: flag,
                val: MultiOption::One(signal)
            });
        }


        // Antenna Noise
        let flag = RadioTapHeaderFlag::AntennaNoise;
        let noise = match packet.get_header_flag_value(flag) {
            MultiOption::One(noise) => Some(noise),
            MultiOption::Multi(noise) => Some(noise[0].clone()),
            _ => None,
        };
        let noise = if let Some(noise) = noise {
            match noise {
                MultiOption::One(noise) => Some(noise),
                MultiOption::Multi(noise) => Some(noise[0].clone()),
                _ => None
            }
        } else {
            None
        };

        if let Some(noise) = noise {
            // tracing::debug!("noise: {:?}", noise);
            new_header_block.flags += 0x1 << flag as u8;
            new_header_block.fields.push(RadioTapHeaderField {
                id: flag,
                val: MultiOption::One(noise)
            });
        }

        // Antenna Number
        let flag = RadioTapHeaderFlag::Antenna;
        let antenna = match packet.get_header_flag_value(flag) {
            MultiOption::One(antenna) => Some(antenna),
            MultiOption::Multi(antenna) => Some(antenna[0].clone()),
            _ => None,
        };
        let antenna = if let Some(antenna) = antenna {
            match antenna {
                MultiOption::One(antenna) => Some(antenna),
                MultiOption::Multi(antenna) => Some(antenna[0].clone()),
                _ => None
            }
        } else {
            None
        };

        if let Some(antenna) = antenna {
            // tracing::debug!("antenna: {:?}", antenna);
            new_header_block.flags += 0x1 << flag as u8;
            new_header_block.fields.push(RadioTapHeaderField {
                id: flag,
                val: MultiOption::One(antenna)
            });
        }


        // Antenna Number
        // let flag = RadioTapHeaderFlag::Antenna;
        // new_header_block.flags += 0x1 << flag as u8;
        // new_header_block.fields.push(RadioTapHeaderField {
        //     id: flag,
        //     val: MultiOption::One(RadioTapHeaderFieldValue::U8(sniffer_idx))
        // });

        // tracing::debug!("New Header Block: {:#?}", new_header_block);

        self.header_blocks.push(new_header_block);

        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // tracing_subscriber::fmt().with_max_level(// tracing::Level::DEBUG).init();


    #[test]
    fn test_parse_valid_packet() {
        let packet: Vec<u8> = vec![
            0, 0, 8, 0, // Version, Pad, Length
            0, 0, 0, 0, // Flags
            // Content
        ];
        let result = RadioTapHeader::parse(&packet);
        assert!(result.is_ok());
        let header = result.unwrap();
        assert_eq!(header.it_version, 0);
        assert_eq!(header.it_pad, 0);
        assert_eq!(header.it_len, 8);
        assert_eq!(header.header_blocks.len(), 1);
        assert_eq!(header.content.len(), 0);
    }

    #[test]
    fn test_parse_invalid_packet_too_short() {
        let packet: Vec<u8> = vec![0, 0, 8];
        let result = RadioTapHeader::parse(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_to_bytes() {
        let packet: Vec<u8> = vec![
            0, 0, 8, 0, // Version, Pad, Length
            0, 0, 0, 0, // Flags
            // Content
        ];
        let header = RadioTapHeader::parse(&packet).unwrap();
        let bytes = header.as_bytes(vec![]);
        assert_eq!(bytes, packet);
    }

    #[test]
    fn test_get_header_flag_value() {
        let packet: Vec<u8> = vec![
            0x00, 0x00, 0x1a, 0x00, 
            0x2f, 0x48, 0x00, 0x00, 
            0xc6, 0xed, 0x20, 0x23, 0x00, 0x00, 0x00, 0x00, 
            0x10, //flags
            0x02, // Data Rate
            0x6c, 0x09, // Channel Frequency
            0xa0, 0x00, // Channel Flags
            0xc8, // Antenna signal
            0x00, // Antenna num
            0x00, 0x00, // RX flags
        ];
        let header = RadioTapHeader::parse(&packet).unwrap();
        let value = header.get_header_flag_value(RadioTapHeaderFlag::Rate);
        assert!(matches!(value, MultiOption::One(MultiOption::One(RadioTapHeaderFieldValue::U8(0x02)))));

        let value = header.get_header_flag_value(RadioTapHeaderFlag::Antenna);
        assert!(matches!(value, MultiOption::One(MultiOption::One(RadioTapHeaderFieldValue::U8(0x0)))));

        // 2024-11-26T17:42:01.565252Z DEBUG slapy::packets::radio_tap_header: Version: 0, pad: 0, header length: 26
        // 2024-11-26T17:42:01.565279Z DEBUG slapy::packets::radio_tap_header: Got 1 header blocks
        // 2024-11-26T17:42:01.565292Z DEBUG slapy::packets::radio_tap_header: RadioTapHeader - flags: 2f 48 00 00
        // 2024-11-26T17:42:01.565303Z DEBUG slapy::packets::radio_tap_header: RadioTapHeader - length: 26
        // 2024-11-26T17:42:01.565350Z DEBUG slapy::packets::radio_tap_header: RadioTapHeader - fields: c6 ed 20 23 00 00 00 00 10 02 6c 09 a0 00 c8 00 00 00
        // 2024-11-26T17:42:01.565394Z DEBUG slapy::packets::radio_tap_header: Checking bit 0
        // 2024-11-26T17:42:01.565607Z DEBUG slapy::packets::radio_tap_header: Bit 0 (TSFT Mactime) is set with value c6 ed 20 23 00 00 00 00!
        // 2024-11-26T17:42:01.565621Z DEBUG slapy::packets::radio_tap_header: Checking bit 1
        // 2024-11-26T17:42:01.565632Z DEBUG slapy::packets::radio_tap_header: Bit 1 (Flags) is set with value 10!
        // 2024-11-26T17:42:01.565655Z DEBUG slapy::packets::radio_tap_header: Checking bit 2
        // 2024-11-26T17:42:01.565664Z DEBUG slapy::packets::radio_tap_header: Bit 2 (Rate) is set with value 02!
        // 2024-11-26T17:42:01.565677Z DEBUG slapy::packets::radio_tap_header: Checking bit 3
        // 2024-11-26T17:42:01.565719Z DEBUG slapy::packets::radio_tap_header: Bit 3 (Channel) is set with value 6c 09 a0 00!
        // 2024-11-26T17:42:01.565732Z DEBUG slapy::packets::radio_tap_header: Checking bit 5
        // 2024-11-26T17:42:01.565745Z DEBUG slapy::packets::radio_tap_header: Bit 5 (Antenna signal) is set with value c8!
        // 2024-11-26T17:42:01.565771Z DEBUG slapy::packets::radio_tap_header: Checking bit 11
        // 2024-11-26T17:42:01.565781Z DEBUG slapy::packets::radio_tap_header: Bit 11 (Antenna) is set with value 00!
        // 2024-11-26T17:42:01.565790Z DEBUG slapy::packets::radio_tap_header: Checking bit 14
        // 2024-11-26T17:42:01.565800Z DEBUG slapy::packets::radio_tap_header: Bit 14 (RX flags) is set with value 00 00!
    }

    #[test]
    fn test_add_sniffer_measurement() {
        // tracing_subscriber::fmt().with_max_level(// tracing::Level::DEBUG).init();

        let packet: Vec<u8> = vec![
            0x00, 0x00, 0x1a, 0x00, 
            0x2f, 0x48, 0x00, 0x00, 
            0xc6, 0xed, 0x20, 0x23, 0x00, 0x00, 0x00, 0x00, 
            0x10, //flags
            0x02, // Data Rate
            0x6c, 0x09, // Channel Frequency
            0xa0, 0x00, // Channel Flags
            0xc8, // Antenna signal
            0x00, // Antenna num
            0x00, 0x00, // RX flags
            // Content - none
        ];

        let packet_2: Vec<u8> = vec![
            0x00, 0x00, 0x1a, 0x00, 
            0x2f, 0x48, 0x00, 0x00, 
            0xc6, 0xed, 0x20, 0x23, 0x00, 0x00, 0x00, 0x00, 
            0x10, //flags
            0x02, // Data Rate
            0x6c, 0x09, // Channel Frequency
            0xa0, 0x00, // Channel Flags
            0x9e, // Antenna signal
            0x05, // Antenna num
            0x00, 0x00, // RX flags
            // Content - none
        ];
        let mut header_1 = RadioTapHeader::parse(&packet).unwrap();
        let header_2 = RadioTapHeader::parse(&packet_2).unwrap();
        let new_header = header_1.add_sniffer_measurement(&header_2);

        // tracing::debug!("New Header: {:#?}", new_header);

        assert_eq!(new_header.header_blocks.len(), 2);
        let last_block = new_header.header_blocks.last().unwrap();
        assert_eq!(last_block.flags, 2088);
        let antenna_field = last_block.fields.iter().find(|f| f.id == RadioTapHeaderFlag::Antenna).unwrap();
        assert!(matches!(antenna_field.val, MultiOption::One(RadioTapHeaderFieldValue::U8(5))));
    }

    #[test]
    fn test_add_sniffer_measurement_to_bytes() {
        // tracing_subscriber::fmt().with_max_level(// tracing::Level::DEBUG).init();

        let packet: Vec<u8> = vec![
            0x00, 0x00, 0x1a, 0x00, 
            0x2f, 0x48, 0x00, 0x00, 
            0xc6, 0xed, 0x20, 0x23, 0x00, 0x00, 0x00, 0x00, 
            0x10, //flags
            0x02, // Data Rate
            0x6c, 0x09, // Channel Frequency
            0xa0, 0x00, // Channel Flags
            0xc8, // Antenna signal
            0x00, // Antenna num
            0x00, 0x00, // RX flags
            // Content - none
        ];

        let packet_2: Vec<u8> = vec![
            0x00, 0x00, 0x1a, 0x00, 
            0x2f, 0x48, 0x00, 0x00, 
            0xc6, 0xed, 0x20, 0x23, 0x00, 0x00, 0x00, 0x00, 
            0x10, //flags
            0x02, // Data Rate
            0x6c, 0x09, // Channel Frequency
            0xa0, 0x00, // Channel Flags
            0x9e, // Antenna signal
            0x0a, // Antenna num
            0x00, 0x00, // RX flags
            // Content - none
        ];
        let mut header_1 = RadioTapHeader::parse(&packet).unwrap();
        let header_2 = RadioTapHeader::parse(&packet_2).unwrap();
        let new_header = header_1.add_sniffer_measurement(&header_2);

        let bytes = new_header.as_bytes(vec![]);

        // tracing::debug!("Bytes: {}", bytes_to_hex_with_sep(&bytes, ' '));

        let expected_bytes: Vec<u8> = vec![
            0x00, 0x00, 0x28, 0x00, 
            
            
            0x2f, 0x48, 0x00, 0xa0,  // Old Header Flags
            0x28, 0x08, 0x00, 0x00,  // New Header Flags
            0x00, 0x00, 0x00, 0x00, // Padding
            0xc6, 0xed, 0x20, 0x23, 0x00, 0x00, 0x00, 0x00, 
            0x10, //flags
            0x02, // Data Rate
            0x6c, 0x09, // Channel Frequency
            0xa0, 0x00, // Channel Flags
            0xc8, // Antenna signal
            0x00, // Antenna num
            0x00, 0x00, // RX flags
            
            // New Header Block
            0x6c, 0x09, // Channel Frequency
            0xa0, 0x00, // Channel Flags
            0x9e, // Antenna signal
            0x0a, // Antenna num
            
            // Content - none
        ];

        assert_eq!(bytes, expected_bytes, "Received Bytes do not match exprected:\n{}\n{}", bytes_to_hex_with_sep(&bytes, ' '), bytes_to_hex_with_sep(&expected_bytes, ' '));
    }

    #[test]
    fn test_update_first_header_flag_value_by_inserting() {
        // Create a RadioTapHeader with initial values
        let packet: Vec<u8> = vec![
            0x00, 0x00, 0x08, 0x00, // Header Version, Pad, Length
            0x00, 0x00, 0x00, 0x00, // Flags
            // No content
        ];
        let header = RadioTapHeader::parse(&packet).unwrap();

        // Update the Antenna field
        let updated_header = header.update_first_header_flag_value(
            RadioTapHeaderFlag::Antenna,
            RadioTapHeaderField {
                id: RadioTapHeaderFlag::Antenna,
                val: MultiOption::One(RadioTapHeaderFieldValue::U8(0x05)), // New antenna value
            },
        );

        // Verify that the flag is set in the first header block
        assert_eq!(
            updated_header.header_blocks[0].flags & (1 << RadioTapHeaderFlag::Antenna as u8),
            1 << RadioTapHeaderFlag::Antenna as u8
        );

        // Verify that the field value is updated
        // if let Some(RadioTapHeaderFieldValue::U8(antenna)) = updated_header
        //     .get_header_flag_value(RadioTapHeaderFlag::Antenna)
        //     .get_one()
        //     .and_then(|val| val.get_one())
        // {
        //     assert_eq!(antenna, 0x05);
        // } else {
        //     panic!("Antenna field not found or incorrect type");
        // }

        // Convert to bytes and verify
        let bytes = updated_header.as_bytes(vec![]);
        let expected_bytes = vec![
            0x00, 0x00, 0x09, 0x00, // Header Version, Pad, Length
            0x00, 0x08, 0x00, 0x00, // Flags with Antenna bit set
            0x05,                   // Antenna value
            // No content
        ];
        assert_eq!(bytes, expected_bytes, "Bytes do not match expected bytes");
    }

    #[test]
    fn test_update_first_header_flag_value_by_replacing() {
        // Create a RadioTapHeader with initial values
        let packet: Vec<u8> = vec![
            0x00, 0x00, 0x08, 0x00, // Header Version, Pad, Length
            0x00, 0x08, 0x00, 0x00, // Flags
            0x00,
            // No content
        ];
        let header = RadioTapHeader::parse(&packet).unwrap();

        // Update the Antenna field
        let updated_header = header.update_first_header_flag_value(
            RadioTapHeaderFlag::Antenna,
            RadioTapHeaderField {
                id: RadioTapHeaderFlag::Antenna,
                val: MultiOption::One(RadioTapHeaderFieldValue::U8(0x05)), // New antenna value
            },
        );

        // Verify that the flag is set in the first header block
        assert_eq!(
            updated_header.header_blocks[0].flags & (1 << RadioTapHeaderFlag::Antenna as u8),
            1 << RadioTapHeaderFlag::Antenna as u8
        );

        // Verify that the field value is updated
        // if let Some(RadioTapHeaderFieldValue::U8(antenna)) = updated_header
        //     .get_header_flag_value(RadioTapHeaderFlag::Antenna)
        //     .get_one()
        //     .and_then(|val| val.get_one())
        // {
        //     assert_eq!(antenna, 0x05);
        // } else {
        //     panic!("Antenna field not found or incorrect type");
        // }

        // Convert to bytes and verify
        let bytes = updated_header.as_bytes(vec![]);
        let expected_bytes = vec![
            0x00, 0x00, 0x09, 0x00, // Header Version, Pad, Length
            0x00, 0x08, 0x00, 0x00, // Flags with Antenna bit set
            0x05,                   // Antenna value
            // No content
        ];
        assert_eq!(bytes, expected_bytes, "Bytes do not match expected bytes");
    }

}
