//! Fingerprinting functionalities
use std::collections::HashMap;
use std::str;
use std::vec;

use crate::packets::management_frames::Dot11ProbeRequest;
use crate::utils::bytes_to_hex;

const VIOLA: &str = "tags;supra;extrates;extcap;htcap;htmcs;htext;httx;htasel;htagg";
const _VANHOEF: &str =
    "tags;supra;extrates;extcap;htcap;htmcs;htext;httx;htasel;htampdu;interworking;wps_uuid";
const _VANHOEF2: &str =
    "tags;supra;extrates;extcap;htmcs;htext;httx;htasel;htampdu;interworking;wps_uuid";

pub fn get_fingerprint(probe: &Dot11ProbeRequest, template: Option<String>) -> String {
    let fingerprint: String;

    let mut ie_parts: Vec<String> = vec![];
    let (ie_data, tags) = parse_probe(probe);
    let mut map: HashMap<String, String> = HashMap::new();
    for (key, value) in ie_data {
        map.insert(key, value);
    }

    for template_part in template.unwrap_or(VIOLA.to_string()).split(";") {
        if map.contains_key(template_part) {
            ie_parts.push(format!("{}:{}", template_part, map[template_part]));
        }
    }

    fingerprint = vec![tags.join(","), ie_parts.join(",")].join(",");

    fingerprint
}

pub fn get_template(probe: &Dot11ProbeRequest) -> String {
    let (ie_data, _) = parse_probe(probe);
    let tags: Vec<String> = ie_data.into_iter().map(|x| x.0).collect();
    "tags;".to_string() + &tags.join(";")
}

fn parse_probe(probe: &Dot11ProbeRequest) -> (Vec<(String, String)>, Vec<String>) {
    let mut ie_data: Vec<(String, String)> = Vec::new();
    let mut tags_field: Vec<String> = Vec::new();

    for i in 0..probe.ies.len() {
        let ie = &probe.ies[i];
        let mut tag = ie.id.to_string();
        // println!("{:?}", ie);

        match ie.id {
            0 => {
                if ie.len > 0 {
                    // ie_data.push(("ssid".to_string(), str::from_utf8(&ie.value).unwrap().to_string());
                }
            }

            1 => {
                ie_data.push(("supra".to_string(), format!("{}", bytes_to_hex(&ie.value))));
            }

            2 => {
                ie_data.push(("2".to_string(), format!("{}", bytes_to_hex(&ie.value))));
            }

            3 => {
                ie_data.push((
                    "DS_channel".to_string(),
                    format!("{}", bytes_to_hex(&ie.value)),
                ));
            }

            4 => {
                ie_data.push(("4".to_string(), format!("{}", bytes_to_hex(&ie.value))));
            }

            5 => {
                ie_data.push(("5".to_string(), format!("{}", bytes_to_hex(&ie.value))));
            }

            6 => {
                ie_data.push(("6".to_string(), format!("{}", bytes_to_hex(&ie.value))));
            }

            7 => {
                ie_data.push(("7".to_string(), format!("{}", bytes_to_hex(&ie.value))));
            }

            8 => {
                ie_data.push(("8".to_string(), format!("{}", bytes_to_hex(&ie.value))));
            }

            9 => {
                ie_data.push(("9".to_string(), format!("{}", bytes_to_hex(&ie.value))));
            }

            10 => {
                ie_data.push((
                    "Req_country_info".to_string(),
                    format!("{}", bytes_to_hex(&ie.value)),
                ));
            }

            11 => {
                ie_data.push(("11".to_string(), format!("{}", bytes_to_hex(&ie.value))));
            }

            28 => {
                ie_data.push(("28".to_string(), format!("{}", bytes_to_hex(&ie.value))));
            }

            45 => {
                // TODO
                if ie.len >= 1 {
                    let mut data: Vec<u8> = vec![];
                    ie.value[0..2].clone_into(&mut data);
                    data.reverse();

                    ie_data.push(("htcap".to_string(), bytes_to_hex(&data)));
                }
                if ie.len >= 2 {
                    ie_data.push(("htagg".to_string(), format!("{:02x}", &ie.value[2])));

                    ie_data.push(("htampdu".to_string(), bytes_to_hex(&ie.value[2..3])));
                }
                if ie.len >= 18 {
                    ie_data.push(("htmcs".to_string(), bytes_to_hex(&ie.value[3..19])));
                }
                if ie.len >= 20 {
                    ie_data.push(("htext".to_string(), bytes_to_hex(&ie.value[19..21])));
                }
                if ie.len >= 24 {
                    ie_data.push(("httx".to_string(), bytes_to_hex(&ie.value[21..25])));
                }
                if ie.len >= 25 {
                    ie_data.push(("htasel".to_string(), format!("{:02x}", &ie.value[25])));
                }
            }

            50 => {
                ie_data.push((
                    "extrates".to_string(),
                    format!("{}", bytes_to_hex(&ie.value)),
                ));
            }

            59 => {
                ie_data.push((
                    "Supported_Operating_Classes_curr".to_string(),
                    format!("{:02x}", ie.value[0]),
                ));

                ie_data.push((
                    "Supported_Operating_Classes_all".to_string(),
                    format!("{:02x}", ie.value[1]),
                ));
            }

            70 => {
                ie_data.push((
                    "RM_En_Cap".to_string(),
                    format!("{}", bytes_to_hex(&ie.value)),
                ));
            }

            107 => {
                ie_data.push(("interworking".to_string(), format!("{:02x}", ie.value[0])));

                // TODO
                // ie_data.push(("interworking_HESSID".to_string(), format!("{}", bytes_to_hex(&ie.value)));
            }

            114 => {
                ie_data.push(("MeshID".to_string(), "".to_string()));
            }

            127 => {
                ie_data.push(("extcap".to_string(), format!("{}", bytes_to_hex(&ie.value))));
            }

            150 => {
                ie_data.push(("150".to_string(), "".to_string()));
                if ie.len > 0 {
                    panic!(
                        "-> Found unknown IE with ID {} (len:{}) and value: {}",
                        ie.id,
                        ie.len,
                        bytes_to_hex(&ie.value)
                    );
                }
            }

            191 => {
                ie_data.push((
                    "VHT_Cap_info".to_string(),
                    format!("{}", bytes_to_hex(&ie.value[0..4])),
                ));

                ie_data.push((
                    "VHT_Sup_MCS".to_string(),
                    format!("{}", bytes_to_hex(&ie.value[4..])),
                ));
            }

            221 => {
                let vendor = bytes_to_hex(&ie.value[0..3]);
                let mut vendor_type = "".to_string();
                let mut vendor_data = "".to_string();

                if ie.value.len() > 3 {
                    vendor_type = format!("_{:02x}", ie.value[3]);
                    vendor_data = bytes_to_hex(&ie.value[4..]);
                } else {
                    // tracing::warn!("IE: 221 vendor data is too short! {:?}", ie)
                }

                tag = format!("{}_{}{}", ie.id, vendor, vendor_type);

                ie_data.push((tag.clone(), vendor_data));
            }

            255 => {
                let ext_tag = ie.value[0];
                let ext_data = bytes_to_hex(&ie.value[1..]);

                tag = format!("{}_{}", ie.id, ext_tag);

                ie_data.push((tag.clone(), ext_data.clone()));

                match ext_tag {
                    2 => {
                        ie_data.push(("FILS_Req".to_string(), ext_data));
                    }

                    35 => {
                        // TODO
                        // IE_data["HE_MAC"] = data[0:6].hex()
                        // IE_data["HE_PHY"] = data[6:17].hex()
                        // IE_data["HE_supp"] = data[17:21].hex()
                        // IE_data["HE_PPE"] = data[21:27].hex()
                    }

                    108 => {
                        // TODO
                    }

                    _ => {}
                }
            }

            _ => {
                // tracing::warn!(
                //     "-> Found unknown IE with ID {} (len:{}) and value: {}",
                //     ie.id,
                //     ie.len,
                //     bytes_to_hex(&ie.value)
                // );
            }
        }

        tags_field.push(tag);
    }

    (ie_data, tags_field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_fingerprinting() {
        // let mut subscriber = tracing_subscriber::fmt();
        // subscriber = subscriber.with_max_level(tracing::Level::DEBUG);
        // subscriber.init();

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
                let fingerprint = get_fingerprint(&probe, None);
                assert_eq!(fingerprint, "0,1,50,3,45,127,255_35,supra:82848b96,extrates:0c1218243048606c,extcap:0000080400000040000020,htcap:402d,htmcs:ffff0000000000000000000000000000,htext:0000,httx:00000000,htasel:00,htagg:1b", "Got wrong Fingerprint from packet - got: {}",fingerprint);
            }
            Err(e) => {
                panic!("Unable to parse Dot11ProbeRequest! ({})", e);
            }
        }
    }

    #[test]
    fn validate_templating() {
        // let mut subscriber = tracing_subscriber::fmt();
        // subscriber = subscriber.with_max_level(tracing::Level::DEBUG);
        // subscriber.init();

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
                let template = get_template(&probe);
                assert_eq!(
                    template, "tags;supra;extrates;DS_channel;htcap;htagg;htampdu;htmcs;htext;httx;htasel;extcap;255_35",
                    "Got wrong Template from packet - got: {}",
                    template
                );
            }
            Err(e) => {
                panic!("Unable to parse Dot11ProbeRequest! ({})", e);
            }
        }
    }
}
