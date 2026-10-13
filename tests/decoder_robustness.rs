//! Robustness: the MQTT and MQTT-SN decoders must never panic, whatever the input. Mutates
//! valid packets (bit flips, truncation, insertions) and random bytes; the full 3M-iteration
//! run is `WOLFIMQ_FUZZ_ITERATIONS=3000000 cargo test --release --test decoder_robustness`.
use bytes::{Bytes, BytesMut};
use wolf_mqtt::protocol::sn::{SnPacket, TopicIdType};
use wolf_mqtt::protocol::{
    ConnectPacket, MqttPacket, Properties, Property, ProtocolVersion, PublishPacket, QoS,
    SubscriptionOptions,
};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn seeds() -> Vec<Vec<u8>> {
    let will = PublishPacket::new("w/t", Bytes::from_static(b"bye"))
        .with_qos(QoS::AtLeastOnce, None)
        .with_properties(Properties(vec![Property::WillDelayInterval(5)]));
    let mut c5 = ConnectPacket::new("c")
        .with_will(will)
        .with_credentials("u", Bytes::from_static(b"p"));
    c5.properties = Properties(vec![
        Property::SessionExpiryInterval(9),
        Property::ReceiveMaximum(3),
    ]);
    let pkts = vec![
        MqttPacket::Connect(c5.clone()),
        MqttPacket::Connect(c5.with_version(ProtocolVersion::V311)),
        MqttPacket::Publish(
            PublishPacket::new("a/b", Bytes::from_static(b"payload"))
                .with_qos(QoS::ExactlyOnce, Some(7))
                .with_properties(Properties(vec![
                    Property::TopicAlias(2),
                    Property::UserProperty("k".into(), "v".into()),
                    Property::CorrelationData(Bytes::from_static(b"x")),
                ])),
        ),
        MqttPacket::Subscribe {
            packet_id: 3,
            filters: vec![("a/+".into(), SubscriptionOptions::new(QoS::AtLeastOnce))],
            properties: Properties(vec![Property::SubscriptionIdentifier(300)]),
        },
        MqttPacket::Unsubscribe {
            packet_id: 4,
            filters: vec!["a/#".into()],
        },
        MqttPacket::disconnect(0x8E),
        MqttPacket::PubRec {
            packet_id: 9,
            reason_code: 0x87,
        },
        MqttPacket::Auth {
            reason_code: 0x18,
            properties: Properties(vec![Property::AuthenticationMethod("m".into())]),
        },
    ];
    let mut out = Vec::new();
    for p in &pkts {
        for v in [ProtocolVersion::V311, ProtocolVersion::V500] {
            if let Ok(b) = p.to_bytes(v) {
                out.push(b.to_vec());
            }
        }
    }
    let sn = vec![
        SnPacket::Connect {
            will: true,
            clean_session: false,
            duration: 30,
            client_id: "d".into(),
        },
        SnPacket::Publish {
            dup: false,
            qos: 2,
            retain: true,
            topic_id_type: TopicIdType::Normal,
            topic_id: 5,
            msg_id: 6,
            data: Bytes::from_static(b"z"),
        },
        SnPacket::Subscribe {
            dup: false,
            qos: 1,
            topic_id_type: TopicIdType::Normal,
            msg_id: 1,
            topic_id: 0,
            topic_name: Some("a/#".into()),
        },
        SnPacket::Register {
            topic_id: 0,
            msg_id: 2,
            topic_name: "x/y".into(),
        },
        SnPacket::EncapMsg {
            ctrl: 0,
            wireless_node_id: vec![1, 2],
            payload: Bytes::from_static(&[0x02, 0x16]),
        },
    ];
    for p in sn {
        out.push(p.to_bytes().unwrap().to_vec());
    }
    out
}

#[test]
fn decoders_never_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let seeds = seeds();
    let iterations: usize = std::env::var("WOLFIMQ_FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    for i in 0..iterations {
        let mut buf = if i % 4 == 0 {
            let len = rng.below(64);
            (0..len).map(|_| rng.next() as u8).collect::<Vec<u8>>()
        } else {
            seeds[rng.below(seeds.len())].clone()
        };
        for _ in 0..1 + rng.below(4) {
            if buf.is_empty() {
                break;
            }
            let pos = rng.below(buf.len());
            match rng.below(4) {
                0 => buf[pos] = rng.next() as u8,
                1 => buf[pos] ^= 1 << rng.below(8),
                2 => {
                    buf.truncate(pos);
                }
                _ => buf.insert(pos, rng.next() as u8),
            }
        }
        for v in [ProtocolVersion::V311, ProtocolVersion::V500] {
            let _ = MqttPacket::decode(&buf, v, 1 << 20);
            let mut bm = BytesMut::from(&buf[..]);
            while let Ok(Some(_)) = MqttPacket::decode_from(&mut bm, v, 1 << 20) {}
        }
        let mut slice = &buf[..];
        while !slice.is_empty() {
            if SnPacket::decode(&mut slice).is_err() {
                break;
            }
        }
    }
}
