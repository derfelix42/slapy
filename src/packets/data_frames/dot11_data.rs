use std::fmt;

#[derive(Debug, Clone)]
pub struct Dot11DataDataFrame {}

impl Dot11DataDataFrame {
    pub fn parse(_packet: &[u8]) -> Result<Self, String> {
        Ok(Dot11DataDataFrame {})
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let bytes: Vec<u8> = Vec::new();

        bytes
    }
}

impl fmt::Display for Dot11DataDataFrame {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Dot11DataFrame: {:?}", self)
    }
}
