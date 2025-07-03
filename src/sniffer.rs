use uuid::Uuid;

pub struct Sniffer {
    // packet_agg_queue: Arc<PacketQueue<PcapPacketHeader>>,
    // packet_in_queue: Arc<PacketQueue<PcapPacketHeader>>,
    // packet_out_queue: Arc<PacketQueue<JoinHandle<Option<PcapPacketHeader>>>>,
    sniffer_uuid: Uuid,
}

impl Sniffer {
    pub fn new(sniffer_uuid: Uuid) -> Result<Self, String> {
        // let packet_agg_queue = Arc::new(PacketQueue::new());
        // let packet_in_queue = Arc::new(PacketQueue::new());
        // let packet_out_queue: Arc<PacketQueue<JoinHandle<Option<PcapPacketHeader>>>> =
        //     Arc::new(PacketQueue::new());

        Ok(Sniffer {
            // packet_agg_queue,
            // packet_in_queue,
            // packet_out_queue,
            sniffer_uuid,
        })
    }
}
