//! Different util functions
pub mod wifi_iface_utils;

use std::collections::HashMap;
use std::fmt::Write;

use crate::packets::MAC;

/// Check if a MAC Address (`[u8; 6]`) is randomized.
/// This is the case, if the second last bit of the first byte is `1`.
///
/// ```
/// use slapy::utils::is_mac_randomized;
/// use slapy::packets::MAC;
///
/// let mac1 = MAC::new([0; 6]);
/// assert_eq!(is_mac_randomized(&mac1), false);
///
/// let mut mac2 = MAC::new([0; 6]);
/// mac2[0] = 0x2;
/// assert_eq!(is_mac_randomized(&mac2), true);
///
/// let mac3 = MAC::new([0xe0, 0xd0, 0x83, 0xd3, 0x47, 0x7f]);
/// assert_eq!(is_mac_randomized(&mac3), false);
///
/// let mac4 = MAC::new([0x4, 0x7b, 0xcb, 0x2a, 0xea, 0xc]);
/// assert_eq!(is_mac_randomized(&mac4), false);
///
/// let mac5 = MAC::new([0x7a, 0x5f, 0x2d, 0x48, 0xa3, 0x69]);
/// assert_eq!(is_mac_randomized(&mac5), true);
/// ```
pub fn is_mac_randomized(mac: &MAC) -> bool {
    (mac[0] & 0x3) == 2
}

/// Transform a [i64] UNIX timestamp into a MySQL formatted String.
/// Use like:
/// ```rust
/// use slapy::utils::timestamp_to_string;
///
/// let string = timestamp_to_string(0); // Returns "1970-01-01 00:00:00"
/// assert_eq!(string, "1970-01-01 00:00:00");
///
/// let string = timestamp_to_string(1722698375); // Returns "2024-08-03 15:19:35"
/// assert_eq!(string, "2024-08-03 15:19:35");
/// ```
pub fn timestamp_to_string(timestamp: i64) -> String {
    // let datetime: DateTime<Utc> = DateTime::from_timestamp(timestamp, 0).unwrap();
    // datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    "".to_string()
}

pub fn timestamp_to_timestring(timestamp: i64) -> String {
    timestamp_to_string(timestamp)
        .replace(":", "-")
        .replace(" ", "_")
}

/// Convert a frequency:[u32] into a channel number as [u32]. Based on Lookup Table.
///
/// ```
/// use slapy::utils::get_channel_number;
/// assert_eq!(get_channel_number(2412), 1);
/// assert_eq!(get_channel_number(2437), 6);
/// assert_eq!(get_channel_number(2462), 11);
/// assert_eq!(get_channel_number(5230), 46);
/// assert_eq!(get_channel_number(5825), 165);
///
/// // Returns 0 for unknown frequency
/// assert_eq!(get_channel_number(3543), 0);
/// ```
pub fn get_channel_number(frequency: u32) -> u32 {
    let freqs: HashMap<u32, u32> = [
        (2412, 1),
        (2417, 2),
        (2422, 3),
        (2427, 4),
        (2432, 5),
        (2437, 6),
        (2442, 7),
        (2447, 8),
        (2452, 9),
        (2457, 10),
        (2462, 11),
        (2467, 12),
        (2472, 13),
        (2484, 14),
        (5160, 32),
        (5170, 34),
        (5180, 36),
        (5190, 38),
        (5200, 40),
        (5210, 42),
        (5220, 44),
        (5230, 46),
        (5240, 48),
        (5260, 52),
        (5280, 56),
        (5300, 60),
        (5320, 64),
        (5500, 100),
        (5520, 104),
        (5540, 108),
        (5560, 112),
        (5580, 116),
        (5600, 120),
        (5620, 124),
        (5640, 128),
        (5660, 132),
        (5680, 136),
        (5700, 140),
        (5745, 149),
        (5765, 153),
        (5785, 157),
        (5805, 161),
        (5825, 165),
    ]
    .iter()
    .cloned()
    .collect();

    freqs.get(&frequency).copied().unwrap_or(0)
}

/// Convert a given [u8] byte array (\[u8\]) into a hex string like "AB45FB".
///
/// ```
/// use slapy::utils::bytes_to_hex;
///
/// let bytes: [u8; 5] = [1, 2, 3, 4, 5];
/// let hex = bytes_to_hex(&bytes);
/// assert_eq!(hex, "0102030405");
/// ```
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut ret = "".to_string();
    for byte in bytes {
        ret += &format!("{:02x}", byte);
    }
    ret
}

/// Convert a given [u8] byte array (\[u8\]) into a hex string like "AB 45 FB" with a given Separator.
/// ```
/// use slapy::utils::bytes_to_hex_with_sep;
///
/// let bytes: [u8; 5] = [1, 2, 3, 4, 5];
/// let hex = bytes_to_hex_with_sep(&bytes, ' ');
/// assert_eq!(hex, "01 02 03 04 05");
///
/// let bytes: [u8; 5] = [1, 2, 3, 4, 5];
/// assert_eq!(bytes_to_hex_with_sep(&bytes, ':'), "01:02:03:04:05");
/// ```
pub fn bytes_to_hex_with_sep(bytes: &[u8], separator: char) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let capacity = bytes.len() * 3 - 1; // 2 chars per byte + separator, minus 1 for last separator
    let mut ret = String::with_capacity(capacity);

    for (i, &byte) in bytes.iter().enumerate() {
        if i > 0 {
            ret.push(separator);
        }
        write!(ret, "{:02x}", byte).unwrap();
    }
    ret
}

/// Convert a given [u8] byte array (\[u8\]) into a MAC Address string like "AB:45:FB:FF:FF:FF".
pub fn bytes_to_mac(bytes: &[u8]) -> String {
    if bytes.len() != 6 {
        panic!(
            "BytesToMac, provided bytes array is not 6 bytes long - it has {} bytes",
            bytes.len()
        );
    }
    bytes_to_hex_with_sep(bytes, ':')
}

pub fn _calculate_eta() {
    // RadioTap File Header
    // let mut byte_counter: u64 = 24;

    // RadioTap Packet Header + Packet Length
    // byte_counter += data.len() as u64 + 16;

    //     let duration = start.elapsed();
    //     info!("Processed {} packets already ({:.1}%) - processing at {:.1}pkt/s - overall time required: {:.1}s with an ETA: -{:.1}s",
    //         counter,
    //         byte_counter as f64 / pcap_size as f64 * 100.0,
    //         counter as f64 / duration.as_secs_f64(),
    //         duration.as_secs_f64() / byte_counter as f64 * pcap_size as f64,
    //         duration.as_secs_f64() / byte_counter as f64 * pcap_size as f64 - duration.as_secs_f64(),
    //     );
}

// #[cfg(unix)]
// pub async fn handle_interrupt() -> Option<()> {
//     let mut interrupt =
//         tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).unwrap();
//     let mut terminate =
//         tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();

//     tokio::select! {
//         _ = interrupt.recv() => tracing::info!("[unix] interrupt"),
//         _ = terminate.recv() => tracing::info!("[unix] terminate")
//     }

//     None
// }

// #[cfg(windows)]
// pub async fn handle_interrupt() -> Option<()> {
//     let mut ctrl_break = tokio::signal::windows::ctrl_break().unwrap();
//     let mut ctrl_c = tokio::signal::windows::ctrl_c().unwrap();

//     tokio::select! {
//         _ = ctrl_break.recv() => tracing::info!("[windows] CTRL+BREAK"),
//         _ = ctrl_c.recv() => tracing::info!("[windows] CTRL+C")
//     }

//     None
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_get_wifi_channel_from_freq_invalid() {}

    #[test]
    fn check_bytes_to_mac() {
        let bytes: [u8; 6] = [1, 2, 3, 4, 5, 6];
        let mac = bytes_to_mac(&bytes);
        assert_eq!(mac, "01:02:03:04:05:06");
    }

    #[test]
    #[should_panic]
    fn check_bytes_to_mac_panic() {
        let bytes: [u8; 5] = [1, 2, 3, 4, 5];
        let _mac = bytes_to_mac(&bytes);
    }
}
