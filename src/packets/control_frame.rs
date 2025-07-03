use super::{dot11_frame::SequenceControllField, Dot11Frame, MAC};

#[derive(Debug, Clone)]
pub struct Dot11ControlFrame {
    pub dot11frame: Dot11Frame,
    pub frame_sub_type: u8,
    pub addr1: MAC,
    pub addr2: Option<MAC>,
    pub seq_control: Option<SequenceControllField>,
    pub ht_control: Option<[u8; 4]>,
}

impl Dot11ControlFrame {
    pub fn parse_from_dot11_frame(dot11frame: Dot11Frame) -> Result<Self, String> {
        let frame_sub_type = dot11frame.frame_sub_type;
        let addr1 = dot11frame.addr1;
        Ok(Self {
            dot11frame: dot11frame.clone(),
            frame_sub_type,
            addr1,
            addr2: dot11frame.addr2,
            seq_control: dot11frame.seq_control.clone(),
            ht_control: dot11frame.ht_control.clone(),
        })
    }

    pub fn parse(packet: &[u8]) -> Result<Self, String> {
        match Dot11Frame::parse(packet) {
            Ok(dot11frame) => Self::parse_from_dot11_frame(dot11frame),
            Err(e) => Err(format!("Unable to parse Dot11Frame: {e}")),
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut ctrl_frame = Vec::new();
        ctrl_frame.extend_from_slice(&self.dot11frame.frame_control);
        ctrl_frame.extend_from_slice(&self.dot11frame.duration.to_le_bytes());
        ctrl_frame.extend_from_slice(self.addr1.as_bytes());
        if let Some(a2) = self.addr2 {
            ctrl_frame.extend_from_slice(a2.as_bytes());
        }
        if let Some(sc) = self.seq_control {
            ctrl_frame.extend_from_slice(&sc.as_bytes());
        }
        if let Some(ht) = self.ht_control {
            ctrl_frame.extend_from_slice(&ht);
        }
        self.dot11frame.as_bytes(ctrl_frame)
    }
}
