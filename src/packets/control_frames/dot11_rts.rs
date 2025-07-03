use crate::packets::{control_frame::Dot11ControlFrame, MAC};

#[derive(Debug, Clone)]
pub struct Dot11RTS {
    pub control_frame: Dot11ControlFrame,
    pub ra: MAC,
    pub ta: MAC,
}

impl Dot11RTS {
    pub fn parse_from_control_frame(control_frame: Dot11ControlFrame) -> Result<Self, String> {
        if control_frame.frame_sub_type != 0xB {
            // example subtype
            return Err("Not an RTS frame!".to_string());
        }
        let ra = control_frame.addr1;
        let ta = control_frame.addr2.ok_or("Missing TA for RTS!")?;
        Ok(Self {
            control_frame,
            ra,
            ta,
        })
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
