use std::{
    fmt,
    hash::{Hash, Hasher},
    ops::{Index, IndexMut},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::utils::bytes_to_hex_with_sep;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MAC {
    value: [u8; 6],
}

impl MAC {
    pub const BROADCAST: MAC = MAC { value: [255; 6] };
    pub const ERROR: MAC = MAC { value: [0; 6] };

    pub fn new(mac: [u8; 6]) -> Self {
        MAC { value: mac }
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.value
    }

    pub fn to_string(&self) -> String {
        bytes_to_hex_with_sep(&self.value, ':')
    }
}

impl TryFrom<&[u8]> for MAC {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 6] = value.try_into().unwrap();
        Ok(MAC { value: bytes })
    }
}

impl TryFrom<&str> for MAC {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value_str = value.to_string();
        let parts = if value_str.contains(":") {
            value_str.split(':')
        } else {
            value_str.split('-')
        };

        let bytes: Vec<u8> = parts
            .into_iter()
            .map(|part| u8::from_str_radix(part, 16).map_err(|e| e.to_string()))
            .collect::<Result<Vec<u8>, String>>()?;

        match bytes.try_into() {
            Ok(mac) => Ok(MAC { value: mac }),
            Err(e) => Err(format!(
                "Could not interpret string '{value}' as valid MAC Address! {:?}",
                e
            )),
        }
    }
}

impl Index<usize> for MAC {
    type Output = u8;
    fn index(&self, index: usize) -> &Self::Output {
        &self.value[index]
    }
}

impl IndexMut<usize> for MAC {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.value[index]
    }
}

impl Hash for MAC {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl fmt::Display for MAC {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.to_string())
    }
}

// Implement Serialize to convert MAC to a string using `to_string`
impl Serialize for MAC {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// Implement Deserialize to convert a string back to MAC using `TryFrom<&str>`
impl<'de> Deserialize<'de> for MAC {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        MAC::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}
