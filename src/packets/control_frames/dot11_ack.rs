use crate::packets::{control_frame::Dot11ControlFrame, MAC};

#[derive(Debug, Clone)]
pub struct Dot11ACK {
    pub control_frame: Dot11ControlFrame,
    pub ra: MAC,
}

impl Dot11ACK {
    pub fn parse_from_control_frame(control_frame: Dot11ControlFrame) -> Result<Self, String> {
        if control_frame.frame_sub_type != 0xD {
            return Err("Not an ACK frame!".to_string());
        }
        let ra = control_frame.addr1;
        Ok(Self { control_frame, ra })
    }

    pub fn parse(packet: &[u8]) -> Result<Self, String> {
        match Dot11ControlFrame::parse(packet) {
            Ok(cf) => Self::parse_from_control_frame(cf),
            Err(e) => Err(format!("Unable to parse Control Frame: {e}")),
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.control_frame.as_bytes()
    }
}
