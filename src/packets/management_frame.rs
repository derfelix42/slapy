use super::{dot11_frame::SequenceControllField, Dot11Frame, MAC};

// #[derive(Debug, Clone)]
// enum Dot11MgmtFrameTypes {
//     Dot11MgmtAssocReq,
//     Dot11MgmtAssocResp,
//     Dot11MgmtReassocReq,
//     Dot11MgmtReassocResp,
//     Dot11MgmtProbeReq(Dot11ProbeRequest),
//     Dot11MgmtProbeResp,
//     Dot11MgmtTimingAdvert,
//     Dot11MgmtReserved0,
//     Dot11MgmtBeacon(Dot11BeaconFrame),
//     Dot11MgmtAtim,
//     Dot11MgmtDisassoc,
//     Dot11MgmtAuth,
//     Dot11MgmtDeauth,
//     Dot11MgmtAction,
//     Dot11MgmtActionNoAck,
//     Dot11MgmtReserved1,
// }

#[derive(Debug, Clone)]
pub struct Dot11MgmtFrame {
    pub dot11frame: Dot11Frame,
    pub frame_sub_type: u8,

    // Address 1 (6)
    pub addr1: MAC,

    // Address 2 (6)
    pub addr2: MAC,

    // Address 3 (6)
    pub addr3: MAC,

    // Sequence Control (2)
    pub seq_control: SequenceControllField,

    // HT Control (0/4)
    pub ht_control: Option<[u8; 4]>,

    // Frame Body (XXX)
    pub frame_body: Vec<u8>,
}

impl Dot11MgmtFrame {
    pub fn parse_from_dot11_frame(dot11frame: Dot11Frame) -> Result<Self, String> {
        let frame_sub_type = dot11frame.frame_sub_type;

        let addr1 = dot11frame.addr1.clone();
        let addr2 = dot11frame
            .addr2
            .clone()
            .expect("Management Frame does not contain addr2 as expected!");
        let addr3 = dot11frame
            .addr3
            .clone()
            .expect("Management Frame does not contain addr3 as expected!");

        let seq_control = dot11frame
            .seq_control
            .expect("Management Frame does not contain seq_control as expected!");
        let ht_control = dot11frame.ht_control;

        let mut frame_body = Vec::new();
        frame_body.extend_from_slice(&dot11frame.frame_body);

        Ok(Dot11MgmtFrame {
            dot11frame,
            frame_sub_type,
            addr1,
            addr2,
            addr3,
            seq_control,
            ht_control,
            frame_body,
        })
    }

    pub fn parse(packet: &[u8]) -> Result<Self, String> {
        match Dot11Frame::parse(packet) {
            Ok(dot11frame) => Self::parse_from_dot11_frame(dot11frame),
            Err(e) => Err(format!("Unable to parse Dot11Frame: {e}")),
        }
    }

    pub fn as_bytes(&self, frame_body: Vec<u8>) -> Vec<u8> {
        let mut mgmt_frame: Vec<u8> = Vec::new();

        mgmt_frame.extend_from_slice(&self.dot11frame.frame_control);
        mgmt_frame.extend_from_slice(&self.dot11frame.duration.to_le_bytes());
        mgmt_frame.extend_from_slice(self.addr1.as_bytes());
        mgmt_frame.extend_from_slice(self.addr2.as_bytes());
        mgmt_frame.extend_from_slice(self.addr3.as_bytes());
        mgmt_frame.extend_from_slice(&self.seq_control.as_bytes());

        if let Some(ht) = self.ht_control {
            mgmt_frame.extend_from_slice(&ht);
        }

        mgmt_frame.extend_from_slice(&frame_body);
        // mgmt_frame.extend_from_slice(&self.dot11frame.fcs);

        self.dot11frame.as_bytes(mgmt_frame)
    }
}
