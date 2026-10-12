use bytes::{Bytes, BytesMut};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use wolf_mqtt::protocol::{ConnectPacket, MqttPacket, ProtocolVersion, PublishPacket, QoS};
use wolf_mqtt::server::BrokerServer;

async fn send_packet(stream: &mut TcpStream, packet: MqttPacket) {
    let mut buf = BytesMut::new();
    packet.encode(&mut buf).expect("Failed to encode packet");
    tokio::io::AsyncWriteExt::write_all(stream, &buf)
        .await
        .expect("Failed to write to stream");
}

async fn read_packet(stream: &mut TcpStream) -> MqttPacket {
    let mut buf = BytesMut::with_capacity(1024);
    loop {
        let n = tokio::io::AsyncReadExt::read_buf(stream, &mut buf)
            .await
            .expect("Socket read failed");
        assert!(n > 0, "Unexpected EOF while reading packet");
        let mut slice = &buf[..];
        if let Ok(pkt) = MqttPacket::decode(&mut slice) {
            return pkt;
        }
    }
}

#[tokio::test]
async fn test_retained_message_delivered_to_late_subscribers() {
    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 1. Publisher publishes a retained message and disconnects
    {
        let mut pub_stream = TcpStream::connect(addr).await.unwrap();
        send_packet(
            &mut pub_stream,
            MqttPacket::Connect(ConnectPacket {
                version: ProtocolVersion::V500,
                client_id: "retained_pub_initial".into(),
                clean_start: true,
                keep_alive_sec: 60,
                will: None,
                username: None,
                password: None,
            }),
        )
        .await;

        let connack = timeout(Duration::from_secs(2), read_packet(&mut pub_stream))
            .await
            .unwrap();
        assert!(matches!(connack, MqttPacket::ConnAck { .. }));

        // Send retained publish
        send_packet(
            &mut pub_stream,
            MqttPacket::Publish(PublishPacket {
                topic: "telemetry/unit1/temperature".into(),
                qos: QoS::AtMostOnce,
                retain: true,
                dup: false,
                packet_id: None,
                payload: Bytes::from_static(b"24.5C"),
            }),
        )
        .await;

        // Disconnect publisher
        send_packet(&mut pub_stream, MqttPacket::Disconnect).await;
    }

    // Small delay to ensure server processed the retained store
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 2. Late Subscriber arrives and subscribes to wildcard "telemetry/#"
    {
        let mut sub_stream = TcpStream::connect(addr).await.unwrap();
        send_packet(
            &mut sub_stream,
            MqttPacket::Connect(ConnectPacket {
                version: ProtocolVersion::V500,
                client_id: "retained_sub_late".into(),
                clean_start: true,
                keep_alive_sec: 60,
                will: None,
                username: None,
                password: None,
            }),
        )
        .await;

        let _ = timeout(Duration::from_secs(2), read_packet(&mut sub_stream))
            .await
            .unwrap();

        // Subscribe to wildcard
        send_packet(
            &mut sub_stream,
            MqttPacket::Subscribe {
                packet_id: 10,
                topics: vec![("telemetry/#".into(), QoS::AtMostOnce)],
            },
        )
        .await;

        // First packet must be SUBACK
        let suback = timeout(Duration::from_secs(2), read_packet(&mut sub_stream))
            .await
            .unwrap();
        assert!(matches!(suback, MqttPacket::SubAck { packet_id: 10, .. }));

        // Second packet must be the retained message!
        let retained_delivery = timeout(Duration::from_secs(2), read_packet(&mut sub_stream))
            .await
            .unwrap();

        if let MqttPacket::Publish(pub_pkt) = retained_delivery {
            assert_eq!(pub_pkt.topic, "telemetry/unit1/temperature");
            assert_eq!(pub_pkt.payload, Bytes::from_static(b"24.5C"));
            assert!(pub_pkt.retain, "Retained flag must be preserved");
        } else {
            panic!("Expected MqttPacket::Publish, got {:?}", retained_delivery);
        }

        send_packet(&mut sub_stream, MqttPacket::Disconnect).await;
    }
}

#[tokio::test]
async fn test_retained_message_erased_on_empty_payload() {
    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 1. Publisher publishes retained message
    let mut pub_stream = TcpStream::connect(addr).await.unwrap();
    send_packet(
        &mut pub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "eraser_pub".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;
    let _ = timeout(Duration::from_secs(2), read_packet(&mut pub_stream))
        .await
        .unwrap();

    send_packet(
        &mut pub_stream,
        MqttPacket::Publish(PublishPacket {
            topic: "switches/light1/state".into(),
            qos: QoS::AtMostOnce,
            retain: true,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"ON"),
        }),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 2. Erase the retained message by sending retain=true with empty payload
    send_packet(
        &mut pub_stream,
        MqttPacket::Publish(PublishPacket {
            topic: "switches/light1/state".into(),
            qos: QoS::AtMostOnce,
            retain: true,
            dup: false,
            packet_id: None,
            payload: Bytes::new(), // Zero-length payload
        }),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. New subscriber subscribes to "switches/light1/state"
    let mut sub_stream = TcpStream::connect(addr).await.unwrap();
    send_packet(
        &mut sub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "erased_verify_sub".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;
    let _ = timeout(Duration::from_secs(2), read_packet(&mut sub_stream))
        .await
        .unwrap();

    send_packet(
        &mut sub_stream,
        MqttPacket::Subscribe {
            packet_id: 20,
            topics: vec![("switches/light1/state".into(), QoS::AtMostOnce)],
        },
    )
    .await;

    let suback = timeout(Duration::from_secs(2), read_packet(&mut sub_stream))
        .await
        .unwrap();
    assert!(matches!(suback, MqttPacket::SubAck { packet_id: 20, .. }));

    // Verifying that NO publish is received because retained message was erased
    let timeout_res = timeout(Duration::from_millis(200), read_packet(&mut sub_stream)).await;
    assert!(
        timeout_res.is_err(),
        "Retained message was erased; no publish should be received"
    );
}
