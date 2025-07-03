use core::fmt;

#[derive(serde::Serialize, Debug, Clone)]
pub struct InformationElement {
    pub id: u8,
    pub len: u8,
    pub value: Vec<u8>,
}

impl InformationElement {
    pub fn parse(packet: &[u8]) -> Result<Self, String> {
        if packet.len() < 2 {
            return Err("Packet is too short to be a valid Information Element".into());
        }

        let id: u8 = packet[0];
        let len: u8 = packet[1];

        let mut end = 2 + len as usize;

        if packet.len() < end {
            end = packet.len();
        }

        let mut value: Vec<u8> = packet[2..end as usize].to_vec();
        if len == 2 {
            value = Vec::new();
        }

        Ok(InformationElement { id, len, value })
    }

    pub fn set_value(&mut self, value: Vec<u8>) {
        self.len = value.len() as u8;
        self.value = value;
    }

    pub fn as_bytes(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.id);
        bytes.push(self.len);
        bytes.extend_from_slice(&self.value);
    }
}

impl fmt::Display for InformationElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IE {} ({}) {:?}", self.id, self.len, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_ie() {
        let raw = [0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24];
        let mut value = Vec::new();
        value.push(0x82);
        value.push(0x84);
        value.push(0x8b);
        value.push(0x96);
        value.push(0x8c);
        value.push(0x12);
        value.push(0x98);
        value.push(0x24);

        let ie = InformationElement::parse(&raw).unwrap();
        assert_eq!(ie.id, 1, "IDs are not equal");
        assert_eq!(ie.len, 8, "Lengths are not equal");

        assert_eq!(ie.value, value, "Values are not equal");
    }

    #[test]
    fn ie_to_bytes() {
        let raw = [0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24];
        let ie = InformationElement::parse(&raw).unwrap();
        let mut bytes = Vec::new();
        ie.as_bytes(&mut bytes);
        assert_eq!(raw.to_vec(), bytes, "Bytes to not equal");
    }
}
