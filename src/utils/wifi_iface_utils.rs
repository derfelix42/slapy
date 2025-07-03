// linux implementation
use crate::packets::MAC;
// #[cfg(unix)]
// use pcap::Device;

#[cfg(unix)]
pub fn get_devices() -> Vec<String> {
    // let ignore_list = ["any", "dbus", "nfqueue", "lo"].to_vec();
    // let devices = Device::list().unwrap();
    let mut ret_list = Vec::new();
    // for device in devices {
    //     if ignore_list
    //         .iter()
    //         .find(|&&x| device.name.starts_with(x))
    //         .is_none()
    //     {
    //         ret_list.push(device.name.to_string());
    //     }
    // }

    ret_list
}

#[cfg(unix)]
pub fn set_monitor_mode(dev_name: &str) {
    // tracing::debug!("    - setting iface down");
    std::process::Command::new("ip")
        .args(["link", "set", dev_name, "down"])
        .output()
        .unwrap();

    // tracing::debug!("    - setting iface to monitormode");
    std::process::Command::new("iwconfig")
        .args([dev_name, "mode", "monitor"])
        .output()
        .unwrap();

    // tracing::debug!("    - setting iface up");
    std::process::Command::new("ip")
        .args(["link", "set", dev_name, "up"])
        .output()
        .unwrap();

    // tracing::debug!("    - iface should be in monitormode now");
}

#[cfg(unix)]
pub fn set_wifi_channel(dev_name: &str, channel: u8) {
    std::process::Command::new("iwconfig")
        .args([dev_name, "channel", channel.to_string().as_str()])
        .output()
        .unwrap();
    // tracing::debug!("Set {} to channel {}", dev_name, channel);
}

#[cfg(unix)]
pub fn get_interface_mode(dev_name: &str) -> String {
    let iw_out = String::from_utf8(
        std::process::Command::new("iwconfig")
            .arg(dev_name)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();

    let mut mode = "".to_string();

    for part in iw_out.split(" ") {
        if part.trim().len() > 0 && part.contains("Mode:") {
            mode = part.trim().replace("Mode:", "").to_string();
        }
    }

    mode
}

#[cfg(unix)]
pub fn get_wifi_channel(dev_name: &str) -> u8 {
    let out = std::process::Command::new("iwlist")
        .args([dev_name, "channel"])
        .output()
        .unwrap();

    let s = String::from_utf8(out.stdout).unwrap();
    let mut ch = "0".to_string();
    for line in s.split("\n") {
        if line.trim().contains("Current Frequency") {
            ch = line
                .trim()
                .replace("Current Frequency:", "")
                .split(" ")
                .into_iter()
                .last()
                .unwrap()
                .replace(")", "")
        }
    }

    ch.parse().unwrap()
}

#[cfg(unix)]
/// Get the mac address based on the given device name.
/// Executes `ip a s <dev_name> | grep ether` in the background and does some parsing.
pub fn get_mac_address(dev_name: &str) -> MAC {
    let echo_child = std::process::Command::new("ip")
        .args(["-j", "a", "s", dev_name])
        .output()
        .expect("Failed to run ip command");

    let ip_out = String::from_utf8(echo_child.stdout).unwrap();
    if ip_out.contains("does not exist.") || ip_out.trim().len() == 0 {
        // tracing::warn!("Device {dev_name} is no network device found by `ip` command.");
        return MAC::new([0; 6]);
    }

    let mut mac = "";

    // let parsed = serde_json::from_str::<serde_json::Value>(&ip_out).unwrap();
    // if parsed.is_array() && parsed[0].is_object() {
    //     let obj = &parsed[0];
    //     mac = obj.get("address").unwrap().as_str().unwrap();
    // }

    MAC::try_from(mac).expect("Could not interpret string as valid MAC address")
}

// Windows implementation (TODO)
#[cfg(windows)]
pub fn set_monitor_mode(_device: &str) {
    tracing::error!("Using unsupported feature in windows!");
}

#[cfg(windows)]
pub fn set_wifi_channel(_device: &str, _channel: u8) {
    tracing::error!("Using unsupported feature in windows!");
}

#[cfg(windows)]
pub fn get_devices() -> Vec<String> {
    println!("[Get Wifi Devices] Unsupported Feature on Windows!");
    Vec::new()
}

#[cfg(windows)]
pub fn get_mac_address(_dev_name: &str) -> MAC {
    tracing::error!("Using unsupported feature in windows!");
    MAC::BROADCAST
}

#[cfg(windows)]
pub fn get_interface_mode(_dev_name: &str) -> String {
    tracing::error!("Using unsupported feature in windows!");
    "".to_string()
}

#[cfg(windows)]
pub fn get_wifi_channel(_dev_name: &str) -> u8 {
    tracing::error!("Using unsupported feature in windows!");
    0
}
