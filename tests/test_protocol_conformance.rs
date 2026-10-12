use bytes::{Bytes, BytesMut};
use wolf_mqtt::protocol::{
    ConnectPacket, MqttPacket, PacketError, ProtocolVersion, PublishPacket, QoS,
};
use wolf_mqtt::routing::{TopicError, TopicTrie};

#[test]
fn test_conformance_packet_qos_matrix() {
    // Test QoS 0 (Fire and forget, no packet ID)
    let qos0_publish = MqttPacket::Publish(PublishPacket {
        topic: "telemetry/v1/sensors".into(),
        qos: QoS::AtMostOnce,
        retain: false,
        dup: false,
        packet_id: None,
        payload: Bytes::from_static(b"{\"status\":\"ok\"}"),
    });

    let mut buf = BytesMut::new();
    qos0_publish
        .encode(&mut buf)
        .expect("QoS 0 encoding must succeed");
    let mut read_buf = &buf[..];
    let decoded = MqttPacket::decode(&mut read_buf).expect("QoS 0 decoding must succeed");
    assert_eq!(decoded, qos0_publish);

    // Test QoS 1 with PubAck cycle
    let pub_id = 999;
    let qos1_publish = MqttPacket::Publish(PublishPacket {
        topic: "commands/reboot".into(),
        qos: QoS::AtLeastOnce,
        retain: true,
        dup: true,
        packet_id: Some(pub_id),
        payload: Bytes::from_static(b"force"),
    });

    let mut buf1 = BytesMut::new();
    qos1_publish
        .encode(&mut buf1)
        .expect("QoS 1 encoding must succeed");
    let mut read_buf1 = &buf1[..];
    let decoded1 = MqttPacket::decode(&mut read_buf1).expect("QoS 1 decoding must succeed");
    assert_eq!(decoded1, qos1_publish);

    // Verify corresponding PubAck
    let puback = MqttPacket::PubAck { packet_id: pub_id };
    let mut ack_buf = BytesMut::new();
    puback
        .encode(&mut ack_buf)
        .expect("PubAck encoding must succeed");
    let mut read_ack = &ack_buf[..];
    let decoded_ack = MqttPacket::decode(&mut read_ack).expect("PubAck decoding must succeed");
    assert_eq!(decoded_ack, puback);
}

#[test]
fn test_conformance_v3_and_v5_connect_handling() {
    // Protocol Level 4 (v3.1.1)
    let v3_conn = MqttPacket::Connect(ConnectPacket {
        version: ProtocolVersion::V311,
        client_id: "legacy-sensor-007".into(),
        clean_start: true,
        keep_alive_sec: 120,
    });
    let mut v3_buf = BytesMut::new();
    v3_conn.encode(&mut v3_buf).unwrap();
    let mut read_v3 = &v3_buf[..];
    assert_eq!(MqttPacket::decode(&mut read_v3).unwrap(), v3_conn);

    // Protocol Level 5 (v5.0)
    let v5_conn = MqttPacket::Connect(ConnectPacket {
        version: ProtocolVersion::V500,
        client_id: "modern-gateway-01".into(),
        clean_start: false,
        keep_alive_sec: 30,
    });
    let mut v5_buf = BytesMut::new();
    v5_conn.encode(&mut v5_buf).unwrap();
    let mut read_v5 = &v5_buf[..];
    assert_eq!(MqttPacket::decode(&mut read_v5).unwrap(), v5_conn);
}

#[test]
fn test_conformance_wildcard_hierarchies_and_isolation() {
    let mut trie = TopicTrie::new();

    // Setup complex multi-tenant subscriptions
    trie.subscribe("tenantA/+/sensors/#", "worker_tenantA_all")
        .unwrap();
    trie.subscribe("tenantB/site1/+", "worker_tenantB_site1")
        .unwrap();
    trie.subscribe("$SYS/broker/uptime", "monitor_sys").unwrap();

    // 1. Matches tenantA deep wildcard
    let match_a = trie.matches("tenantA/building3/sensors/temperature/celsius");
    assert!(match_a.contains("worker_tenantA_all"));
    assert!(!match_a.contains("worker_tenantB_site1"));

    // 2. Matches tenantB single wildcard
    let match_b = trie.matches("tenantB/site1/pressure");
    assert!(match_b.contains("worker_tenantB_site1"));
    assert!(!match_b.contains("worker_tenantA_all"));

    // 3. System topic isolation
    let match_sys = trie.matches("$SYS/broker/uptime");
    assert!(match_sys.contains("monitor_sys"));
    assert_eq!(match_sys.len(), 1);

    // 4. Multi-level wildcard subscription rules
    assert_eq!(
        trie.subscribe("invalid/#/path", "bad_client"),
        Err(TopicError::InvalidMultiWildcardPosition)
    );
}

#[test]
fn test_conformance_malformed_truncated_packet_recovery() {
    // Incomplete buffer with missing payload bytes
    let truncated_bytes = [0x30, 0x10, 0x00, 0x04, b't', b'e', b's', b't']; // Remaining length = 16, but only 6 provided
    let mut slice = &truncated_bytes[..];
    assert_eq!(
        MqttPacket::decode(&mut slice),
        Err(PacketError::BufferUnderflow)
    );
}
