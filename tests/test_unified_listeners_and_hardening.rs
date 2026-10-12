use bytes::{Buf, Bytes, BytesMut};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wolf_mqtt::auth::AclEngine;
use wolf_mqtt::protocol::{ConnectPacket, MqttPacket, ProtocolVersion, PublishPacket, QoS};
use wolf_mqtt::server::{BrokerContext, BrokerServer};

async fn send_packet(stream: &mut TcpStream, packet: MqttPacket) {
    let mut buf = BytesMut::new();
    packet.encode(&mut buf).expect("Failed to encode packet");
    stream
        .write_all(&buf)
        .await
        .expect("Failed to send packet over TCP");
    stream.flush().await.expect("Failed to flush TCP stream");
}

async fn read_packet(stream: &mut TcpStream) -> MqttPacket {
    let mut buf = BytesMut::with_capacity(1024);
    loop {
        let mut slice = &buf[..];
        if let Ok(pkt) = MqttPacket::decode(&mut slice) {
            let consumed = buf.len() - slice.len();
            buf.advance(consumed);
            return pkt;
        }
        let bytes_read = stream
            .read_buf(&mut buf)
            .await
            .expect("Failed to read from TCP stream");
        assert!(bytes_read > 0, "Premature EOF while awaiting MQTT packet");
    }
}

#[tokio::test]
async fn test_shared_broker_context_cross_listener_routing() {
    let acl = Arc::new(AclEngine::new(true));
    let shared_context = BrokerContext::new(acl);

    // Listener A (e.g. simulating TCP on port A)
    let server_a = BrokerServer::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_context(shared_context.clone());
    let addr_a = server_a.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server_a.run().await;
    });

    // Listener B (e.g. simulating second listener on port B sharing the exact same context)
    let server_b = BrokerServer::bind("127.0.0.1:0")
        .await
        .unwrap()
        .with_context(shared_context.clone());
    let addr_b = server_b.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server_b.run().await;
    });

    // Client 1 connects to Listener A and subscribes to "fleet/updates"
    let mut client_sub = TcpStream::connect(addr_a).await.unwrap();
    send_packet(
        &mut client_sub,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V311,
            client_id: "subscriber_node".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;
    assert!(matches!(
        read_packet(&mut client_sub).await,
        MqttPacket::ConnAck { .. }
    ));

    send_packet(
        &mut client_sub,
        MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("fleet/updates".into(), QoS::AtLeastOnce)],
        },
    )
    .await;
    assert!(matches!(
        read_packet(&mut client_sub).await,
        MqttPacket::SubAck { .. }
    ));

    // Client 2 connects to Listener B and publishes to "fleet/updates"
    let mut client_pub = TcpStream::connect(addr_b).await.unwrap();
    send_packet(
        &mut client_pub,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V311,
            client_id: "publisher_node".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;
    assert!(matches!(
        read_packet(&mut client_pub).await,
        MqttPacket::ConnAck { .. }
    ));

    send_packet(
        &mut client_pub,
        MqttPacket::Publish(PublishPacket {
            topic: "fleet/updates".into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"FIRMWARE_V2"),
        }),
    )
    .await;

    // Verify Subscriber on Listener A receives the message published through Listener B!
    let delivered = read_packet(&mut client_sub).await;
    if let MqttPacket::Publish(pkt) = delivered {
        assert_eq!(pkt.topic, "fleet/updates");
        assert_eq!(&pkt.payload[..], b"FIRMWARE_V2");
        assert!(
            !pkt.retain,
            "Retain flag must be 0 for forwarded live messages"
        );
    } else {
        panic!("Expected Publish packet, got: {:?}", delivered);
    }
}

#[tokio::test]
async fn test_live_unsubscribe_and_unsuback() {
    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    send_packet(
        &mut client,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V311,
            client_id: "unsub_tester".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;
    assert!(matches!(
        read_packet(&mut client).await,
        MqttPacket::ConnAck { .. }
    ));

    // Subscribe to test/topic
    send_packet(
        &mut client,
        MqttPacket::Subscribe {
            packet_id: 10,
            topics: vec![("test/topic".into(), QoS::AtMostOnce)],
        },
    )
    .await;
    assert!(matches!(
        read_packet(&mut client).await,
        MqttPacket::SubAck { .. }
    ));

    // Unsubscribe from test/topic
    send_packet(
        &mut client,
        MqttPacket::Unsubscribe {
            packet_id: 11,
            topics: vec!["test/topic".into()],
        },
    )
    .await;

    let unsuback = read_packet(&mut client).await;
    assert_eq!(unsuback, MqttPacket::UnsubAck { packet_id: 11 });
}

#[tokio::test]
async fn test_retained_qos1_delivery_with_packet_id() {
    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 1. Publisher publishes retained message with QoS 1
    let mut pub_stream = TcpStream::connect(addr).await.unwrap();
    send_packet(
        &mut pub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V311,
            client_id: "pub_retainer".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;
    assert!(matches!(
        read_packet(&mut pub_stream).await,
        MqttPacket::ConnAck { .. }
    ));

    send_packet(
        &mut pub_stream,
        MqttPacket::Publish(PublishPacket {
            topic: "system/version".into(),
            qos: QoS::AtLeastOnce,
            retain: true,
            dup: false,
            packet_id: Some(55),
            payload: Bytes::from_static(b"v1.0.0-fips"),
        }),
    )
    .await;
    assert_eq!(
        read_packet(&mut pub_stream).await,
        MqttPacket::PubAck { packet_id: 55 }
    );
    send_packet(&mut pub_stream, MqttPacket::Disconnect).await;

    // 2. Late subscriber subscribes to "system/version"
    let mut sub_stream = TcpStream::connect(addr).await.unwrap();
    send_packet(
        &mut sub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V311,
            client_id: "late_sub_node".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;
    assert!(matches!(
        read_packet(&mut sub_stream).await,
        MqttPacket::ConnAck { .. }
    ));

    send_packet(
        &mut sub_stream,
        MqttPacket::Subscribe {
            packet_id: 7,
            topics: vec![("system/version".into(), QoS::AtLeastOnce)],
        },
    )
    .await;
    assert!(matches!(
        read_packet(&mut sub_stream).await,
        MqttPacket::SubAck { .. }
    ));

    // Verify retained message is delivered with valid packet_id and retain=true
    let delivered = read_packet(&mut sub_stream).await;
    if let MqttPacket::Publish(pkt) = delivered {
        assert_eq!(pkt.topic, "system/version");
        assert_eq!(&pkt.payload[..], b"v1.0.0-fips");
        assert!(
            pkt.retain,
            "Retained message must have retain flag set to true"
        );
        assert!(
            pkt.packet_id.is_some(),
            "QoS 1 delivery must have an assigned packet_id"
        );
    } else {
        panic!("Expected retained Publish packet, got: {:?}", delivered);
    }
}

#[tokio::test]
async fn test_duplicate_connect_causes_disconnect() {
    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let conn_pkt = MqttPacket::Connect(ConnectPacket {
        version: ProtocolVersion::V311,
        client_id: "single_session".into(),
        clean_start: true,
        keep_alive_sec: 60,
        will: None,
        username: None,
        password: None,
    });

    // 1st CONNECT -> OK
    send_packet(&mut stream, conn_pkt.clone()).await;
    assert!(matches!(
        read_packet(&mut stream).await,
        MqttPacket::ConnAck { .. }
    ));

    // 2nd CONNECT on same socket -> protocol violation, server closes stream!
    send_packet(&mut stream, conn_pkt).await;

    let mut buf = [0u8; 128];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(
        n, 0,
        "Server must close connection upon receiving second CONNECT"
    );
}

#[tokio::test]
async fn test_qos2_publish_retransmission_deduplication() {
    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 1. Subscriber connects and subscribes
    let mut sub_stream = TcpStream::connect(addr).await.unwrap();
    send_packet(
        &mut sub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V311,
            client_id: "qos2_sub".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;
    assert!(matches!(
        read_packet(&mut sub_stream).await,
        MqttPacket::ConnAck { .. }
    ));

    send_packet(
        &mut sub_stream,
        MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("orders/new".into(), QoS::AtLeastOnce)],
        },
    )
    .await;
    assert!(matches!(
        read_packet(&mut sub_stream).await,
        MqttPacket::SubAck { .. }
    ));

    // 2. Publisher connects
    let mut pub_stream = TcpStream::connect(addr).await.unwrap();
    send_packet(
        &mut pub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V311,
            client_id: "qos2_pub".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;
    assert!(matches!(
        read_packet(&mut pub_stream).await,
        MqttPacket::ConnAck { .. }
    ));

    // 3. Send QoS 2 PUBLISH (packet_id: 501)
    let qos2_pkt = MqttPacket::Publish(PublishPacket {
        topic: "orders/new".into(),
        qos: QoS::ExactlyOnce,
        retain: false,
        dup: false,
        packet_id: Some(501),
        payload: Bytes::from_static(b"ORDER_#1001"),
    });

    send_packet(&mut pub_stream, qos2_pkt.clone()).await;

    // Broker acknowledges with PUBREC
    assert_eq!(
        read_packet(&mut pub_stream).await,
        MqttPacket::PubRec { packet_id: 501 }
    );

    // Subscriber receives the message
    let delivered = read_packet(&mut sub_stream).await;
    if let MqttPacket::Publish(p) = delivered {
        assert_eq!(&p.payload[..], b"ORDER_#1001");
    } else {
        panic!("Expected Publish packet, got: {:?}", delivered);
    }

    // 4. Publisher re-sends the same QoS 2 PUBLISH (simulating network timeout / retry)
    send_packet(&mut pub_stream, qos2_pkt).await;

    // Broker acknowledges again with PUBREC
    assert_eq!(
        read_packet(&mut pub_stream).await,
        MqttPacket::PubRec { packet_id: 501 }
    );

    // Verify subscriber DOES NOT receive a duplicate message (timeout check)
    let duplicate_check = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        sub_stream.read(&mut [0u8; 128]),
    )
    .await;
    assert!(
        duplicate_check.is_err(),
        "Subscriber must not receive duplicate delivery on retransmitted QoS 2 publish"
    );

    // Complete QoS 2 handshake: PUBREL -> PUBCOMP
    send_packet(&mut pub_stream, MqttPacket::PubRel { packet_id: 501 }).await;
    assert_eq!(
        read_packet(&mut pub_stream).await,
        MqttPacket::PubComp { packet_id: 501 }
    );
}

#[tokio::test]
async fn test_lwt_delivery_with_qos1() {
    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 1. Subscriber connects and subscribes to will topic
    let mut sub_stream = TcpStream::connect(addr).await.unwrap();
    send_packet(
        &mut sub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V311,
            client_id: "watcher".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;
    assert!(matches!(
        read_packet(&mut sub_stream).await,
        MqttPacket::ConnAck { .. }
    ));

    send_packet(
        &mut sub_stream,
        MqttPacket::Subscribe {
            packet_id: 2,
            topics: vec![("cluster/lwt".into(), QoS::AtLeastOnce)],
        },
    )
    .await;
    assert!(matches!(
        read_packet(&mut sub_stream).await,
        MqttPacket::SubAck { .. }
    ));

    // 2. Publisher connects with QoS 1 Will (no packet_id initially)
    let mut pub_stream = TcpStream::connect(addr).await.unwrap();
    let will = PublishPacket {
        topic: "cluster/lwt".into(),
        qos: QoS::AtLeastOnce, // QoS 1 Will!
        retain: false,
        dup: false,
        packet_id: None,
        payload: Bytes::from_static(b"CRASHED_QOS1"),
    };

    send_packet(
        &mut pub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V311,
            client_id: "crasher".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: Some(will),
            username: None,
            password: None,
        }),
    )
    .await;
    assert!(matches!(
        read_packet(&mut pub_stream).await,
        MqttPacket::ConnAck { .. }
    ));

    // 3. Publisher abruptly drops connection
    drop(pub_stream);

    // 4. Subscriber must receive the QoS 1 LWT message with a valid assigned packet_id!
    let delivered = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_packet(&mut sub_stream),
    )
    .await
    .expect("LWT delivery timeout");

    if let MqttPacket::Publish(pkt) = delivered {
        assert_eq!(pkt.topic, "cluster/lwt");
        assert_eq!(&pkt.payload[..], b"CRASHED_QOS1");
        assert_eq!(pkt.qos, QoS::AtLeastOnce);
        assert!(
            pkt.packet_id.is_some(),
            "Delivered QoS 1 LWT must have assigned packet_id"
        );
    } else {
        panic!("Expected LWT Publish, got: {:?}", delivered);
    }
}

#[tokio::test]
async fn test_mqtt5_connack_raw_properties_field() {
    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    send_packet(
        &mut stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500, // MQTT 5.0!
            client_id: "v5_raw_probe".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;

    // Read exact raw wire bytes of CONNACK
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).await.unwrap();
    assert!(n >= 5, "CONNACK for MQTT 5 must be at least 5 bytes");
    assert_eq!(buf[0], 0x20, "Fixed header byte must be 0x20 (CONNACK)");
    assert_eq!(
        buf[1], 0x03,
        "Remaining length for MQTT 5 CONNACK must be 3 (flags + reason + props_len)"
    );
    assert_eq!(buf[2], 0x00, "Session present flag");
    assert_eq!(buf[3], 0x00, "Success reason code");
    assert_eq!(buf[4], 0x00, "Property length must be present and 0");
}
