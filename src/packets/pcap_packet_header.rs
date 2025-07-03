use uuid::Uuid;

use crate::utils::bytes_to_hex_with_sep;
use std::time::Duration;

use super::RadioTapHeader;

#[derive(Debug, Clone)]
pub struct PcapPacketHeader {
    pub timestamp: Duration,
    pub capture_start_timestamp: Duration,
    pub sniffer_uuid: Uuid,
    pub caplen: u32,
    pub len: u32,
    pub data: Vec<u8>,
    pub radio_tap_header: Option<RadioTapHeader>,
}

impl PcapPacketHeader {
    pub fn new(
        timestamp: Duration,
        capture_start_timestamp: Duration,
        sniffer_uuid: Uuid,
        len: u32,
        data: Vec<u8>,
    ) -> Result<Self, String> {
        Ok(PcapPacketHeader {
            timestamp,
            capture_start_timestamp,
            sniffer_uuid,
            caplen: len,
            len,
            data,
            radio_tap_header: None,
        })
    }

    pub fn set_radio_tap_header(&mut self, header: RadioTapHeader) -> Self {
        self.radio_tap_header = Some(header);
        self.clone()
    }

    pub fn overwrite_data_from_rth(&mut self, data: Vec<u8>) {
        self.data = data;
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Self, String> {
        let timestamp = Duration::from_secs_f64(f64::from_le_bytes(
            data[0..8].try_into().expect("Could not parse bytes"),
        ));
        let capture_start_timestamp = Duration::from_secs_f64(f64::from_le_bytes(
            data[8..16].try_into().expect("Could not parse bytes"),
        ));
        let sniffer_uuid =
            Uuid::from_bytes(data[16..32].try_into().expect("Could not parse bytes"));
        let caplen = u32::from_le_bytes(data[32..36].try_into().expect("Could not parse bytes"));
        let len = u32::from_le_bytes(data[36..40].try_into().expect("Could not parse bytes"));
        let bytes = data[40..].to_vec();

        Ok(PcapPacketHeader {
            timestamp,
            capture_start_timestamp,
            sniffer_uuid,
            caplen,
            len,
            data: bytes,
            radio_tap_header: None,
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // tracing::debug!("PcapPacketHeader: {:?}", self);

        data.extend_from_slice(&self.timestamp.as_secs_f64().to_le_bytes());
        // tracing::debug!(
        //     "timestamp: {}",
        //     bytes_to_hex_with_sep(&self.timestamp.as_secs_f64().to_le_bytes(), ' ')
        // );

        data.extend_from_slice(&self.capture_start_timestamp.as_secs_f64().to_le_bytes());
        // tracing::debug!(
        //     "capture_start_timestamp: {}",
        //     bytes_to_hex_with_sep(
        //         &self.capture_start_timestamp.as_secs_f64().to_le_bytes(),
        //         ' '
        //     )
        // );

        data.extend_from_slice(self.sniffer_uuid.as_bytes());
        // tracing::debug!(
        //     "sniffer_uuid: {}",
        //     bytes_to_hex_with_sep(self.sniffer_uuid.as_bytes(), ' ')
        // );

        data.extend_from_slice(&self.caplen.to_le_bytes());
        // tracing::debug!(
        //     "caplen: {}",
        //     bytes_to_hex_with_sep(&self.caplen.to_le_bytes(), ' ')
        // );

        data.extend_from_slice(&self.len.to_le_bytes());
        // tracing::debug!(
        //     "len: {}",
        //     bytes_to_hex_with_sep(&self.len.to_le_bytes(), ' ')
        // );

        data.extend_from_slice(&self.data);
        // tracing::debug!("data: {}", bytes_to_hex_with_sep(&self.data, ' '));

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcap_packet_header_new() {
        let timestamp = Duration::from_secs(1625159078);
        let capture_start_timestamp = Duration::from_secs(1625150000);
        let sniffer_uuid = Uuid::new_v4();
        let len = 1024;
        let data = vec![1, 2, 3, 4, 5];

        let header = PcapPacketHeader::new(
            timestamp,
            capture_start_timestamp,
            sniffer_uuid,
            len,
            data.clone(),
        )
        .expect("Failed to create PcapPacketHeader");

        assert_eq!(header.timestamp, timestamp);
        assert_eq!(header.capture_start_timestamp, capture_start_timestamp);
        assert_eq!(header.sniffer_uuid, sniffer_uuid);
        assert_eq!(header.caplen, len);
        assert_eq!(header.len, len);
        assert_eq!(header.data, data);
        assert!(header.radio_tap_header.is_none());
    }

    #[test]
    fn test_pcap_packet_header_as_bytes_and_from_bytes() {
        let timestamp = Duration::from_secs_f64(1625159078.123);
        let capture_start_timestamp = Duration::from_secs_f64(1625150000.456);
        let sniffer_uuid = Uuid::new_v4();
        let len = 2048;
        let data = vec![10, 20, 30, 40, 50];

        let header = PcapPacketHeader::new(
            timestamp,
            capture_start_timestamp,
            sniffer_uuid,
            len,
            data.clone(),
        )
        .expect("Failed to create PcapPacketHeader");

        let bytes = header.as_bytes();
        let parsed_header = PcapPacketHeader::from_bytes(bytes).expect("Failed to parse bytes");

        assert_eq!(parsed_header.timestamp, timestamp);
        assert_eq!(
            parsed_header.capture_start_timestamp,
            capture_start_timestamp
        );
        assert_eq!(parsed_header.sniffer_uuid, sniffer_uuid);
        assert_eq!(parsed_header.caplen, len);
        assert_eq!(parsed_header.len, len);
        assert_eq!(parsed_header.data, data);
        assert!(parsed_header.radio_tap_header.is_none());
    }

    // #[test]
    // fn test_pcap_packet_header_set_radio_tap_header() {
    //     let timestamp = Duration::from_secs(1625159078);
    //     let capture_start_timestamp = Duration::from_secs(1625150000);
    //     let sniffer_uuid = Uuid::new_v4();
    //     let len = 512;
    //     let data = vec![5, 4, 3, 2, 1];

    //     let mut header = PcapPacketHeader::new(
    //         timestamp,
    //         capture_start_timestamp,
    //         sniffer_uuid,
    //         len,
    //         data.clone(),
    //     )
    //     .expect("Failed to create PcapPacketHeader");

    //     let radio_tap_header = RadioTapHeader { /* fields */ };
    //     header = header.set_radio_tap_header(radio_tap_header.clone());

    //     assert_eq!(header.radio_tap_header, Some(radio_tap_header));
    // }
}
