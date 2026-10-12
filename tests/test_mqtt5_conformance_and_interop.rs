use bytes::{BufMut, Bytes, BytesMut};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use wolf_mqtt::auth::AclEngine;
use wolf_mqtt::protocol::vbi::encode_variable_byte_integer;
use wolf_mqtt::protocol::{ConnectPacket, MqttPacket, ProtocolVersion, PublishPacket, QoS};
use wolf_mqtt::server::BrokerServer;

async fn read_packet(stream: &mut TcpStream) -> MqttPacket {
    let mut buf = BytesMut::with_capacity(1024);
    loop {
        let mut slice = &buf[..];
        if !slice.is_empty() {
            if let Ok(packet) = MqttPacket::decode(&mut slice) {
                return packet;
            }
        }
        let n = stream.read_buf(&mut buf).await.expect("Read packet failed");
        assert!(n > 0, "Unexpected EOF while reading packet from broker");
    }
}

async fn send_packet(stream: &mut TcpStream, packet: MqttPacket) {
    let mut buf = BytesMut::new();
    packet
        .encode(&mut buf)
        .expect("Encoding packet must succeed");
    stream.write_all(&buf).await.expect("Write must succeed");
}

#[tokio::test]
async fn test_mqtt5_live_tcp_pub_sub_exchange() {
    let server = BrokerServer::bind("127.0.0.1:0")
        .await
        .expect("Broker bind failed");
    let server_addr = server.local_addr().expect("Failed to get local addr");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. MQTT 5.0 Subscriber connects
    let mut sub_stream = TcpStream::connect(server_addr)
        .await
        .expect("Sub connect failed");
    send_packet(
        &mut sub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "mqtt5-subscriber".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;

    let sub_connack = timeout(Duration::from_secs(2), read_packet(&mut sub_stream))
        .await
        .expect("Sub ConnAck timeout");
    assert_eq!(
        sub_connack,
        MqttPacket::ConnAck {
            session_present: false,
            reason_code: 0x00,
        }
    );

    // Subscribe to topic
    send_packet(
        &mut sub_stream,
        MqttPacket::Subscribe {
            packet_id: 10,
            topics: vec![("telemetry/v5/sensors".into(), QoS::AtLeastOnce)],
        },
    )
    .await;

    let suback = timeout(Duration::from_secs(2), read_packet(&mut sub_stream))
        .await
        .expect("SubAck timeout");
    assert_eq!(
        suback,
        MqttPacket::SubAck {
            packet_id: 10,
            return_codes: vec![0x01],
        }
    );

    // 2. MQTT 5.0 Publisher connects
    let mut pub_stream = TcpStream::connect(server_addr)
        .await
        .expect("Pub connect failed");
    send_packet(
        &mut pub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "mqtt5-publisher".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;

    let pub_connack = timeout(Duration::from_secs(2), read_packet(&mut pub_stream))
        .await
        .expect("Pub ConnAck timeout");
    assert_eq!(
        pub_connack,
        MqttPacket::ConnAck {
            session_present: false,
            reason_code: 0x00,
        }
    );

    // Publish QoS 1 message
    send_packet(
        &mut pub_stream,
        MqttPacket::Publish(PublishPacket {
            topic: "telemetry/v5/sensors".into(),
            qos: QoS::AtLeastOnce,
            retain: false,
            dup: false,
            packet_id: Some(555),
            payload: Bytes::from_static(b"{\"temp\": 23.4, \"protocol\": \"mqtt5\"}"),
        }),
    )
    .await;

    let puback = timeout(Duration::from_secs(2), read_packet(&mut pub_stream))
        .await
        .expect("PubAck timeout");
    assert_eq!(puback, MqttPacket::PubAck { packet_id: 555 });

    // Verify subscriber receives the message
    let delivered = timeout(Duration::from_secs(2), read_packet(&mut sub_stream))
        .await
        .expect("Message delivery timeout");
    if let MqttPacket::Publish(pkt) = delivered {
        assert_eq!(pkt.topic, "telemetry/v5/sensors");
        assert_eq!(
            &pkt.payload[..],
            b"{\"temp\": 23.4, \"protocol\": \"mqtt5\"}"
        );
    } else {
        panic!("Expected Publish packet, got: {:?}", delivered);
    }
}

#[tokio::test]
async fn test_mqtt5_connect_frame_with_properties() {
    let server = BrokerServer::bind("127.0.0.1:0")
        .await
        .expect("Broker bind failed");
    let server_addr = server.local_addr().expect("Failed to get local addr");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(server_addr)
        .await
        .expect("Connect failed");

    // Manually build an MQTT 5.0 CONNECT frame containing User Properties and Session Expiry
    let mut raw = BytesMut::new();
    raw.put_u8(0x10); // Connect header

    let mut payload = BytesMut::new();
    payload.put_u16(4);
    payload.put_slice(b"MQTT");
    payload.put_u8(5); // Version 5.0
    payload.put_u8(0x02); // Clean start
    payload.put_u16(30); // Keep alive: 30s

    // Properties: Length = 5 bytes (Session Expiry Interval = 300 seconds)
    payload.put_u8(5);
    payload.put_u8(0x11);
    payload.put_u32(300);

    // Client ID
    payload.put_u16(15);
    payload.put_slice(b"mqtt5-props-cli");

    encode_variable_byte_integer(payload.len() as u32, &mut raw).unwrap();
    raw.put(payload);

    stream
        .write_all(&raw)
        .await
        .expect("Write raw connect failed");

    // Broker must successfully parse properties and return ConnAck
    let connack = timeout(Duration::from_secs(2), read_packet(&mut stream))
        .await
        .expect("ConnAck timeout");
    assert_eq!(
        connack,
        MqttPacket::ConnAck {
            session_present: false,
            reason_code: 0x00,
        }
    );
}

#[tokio::test]
async fn test_mqtt5_lwt_delivery_with_will_properties() {
    let server = BrokerServer::bind("127.0.0.1:0")
        .await
        .expect("Broker bind failed");
    let server_addr = server.local_addr().expect("Failed to get local addr");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. Subscriber connects
    let mut sub_stream = TcpStream::connect(server_addr)
        .await
        .expect("Sub connect failed");
    send_packet(
        &mut sub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "lwt_watcher_v5".into(),
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
            topics: vec![("cluster/nodes/+/lwt".into(), QoS::AtMostOnce)],
        },
    )
    .await;
    assert!(matches!(
        read_packet(&mut sub_stream).await,
        MqttPacket::SubAck { .. }
    ));

    // 2. Node connects with MQTT 5.0 LWT containing will properties
    let mut node_stream = TcpStream::connect(server_addr)
        .await
        .expect("Node connect failed");

    let mut raw = BytesMut::new();
    raw.put_u8(0x10);

    let mut payload = BytesMut::new();
    payload.put_u16(4);
    payload.put_slice(b"MQTT");
    payload.put_u8(5); // v5
    payload.put_u8(0x06); // Clean start (0x02) | Will Flag (0x04)
    payload.put_u16(20);

    // Connect properties: 0 length
    payload.put_u8(0x00);

    // Client ID
    payload.put_u16(6);
    payload.put_slice(b"node01");

    // Will properties: length 5 (Will delay interval)
    payload.put_u8(5);
    payload.put_u8(0x18);
    payload.put_u32(1);

    // Will topic
    payload.put_u16(22);
    payload.put_slice(b"cluster/nodes/01/lwt");

    // Will payload
    payload.put_u16(11);
    payload.put_slice(b"UNEXPECTED");

    encode_variable_byte_integer(payload.len() as u32, &mut raw).unwrap();
    raw.put(payload);

    node_stream
        .write_all(&raw)
        .await
        .expect("Write connect failed");
    assert!(matches!(
        read_packet(&mut node_stream).await,
        MqttPacket::ConnAck { .. }
    ));

    // 3. Abrupt disconnect by dropping node stream
    drop(node_stream);

    // 4. Verify subscriber receives the LWT message
    let lwt_msg = timeout(Duration::from_secs(2), read_packet(&mut sub_stream))
        .await
        .expect("LWT message timeout");
    if let MqttPacket::Publish(pkt) = lwt_msg {
        assert_eq!(pkt.topic, "cluster/nodes/01/lwt");
        assert_eq!(&pkt.payload[..], b"UNEXPECTED");
    } else {
        panic!("Expected LWT Publish packet, got: {:?}", lwt_msg);
    }
}

#[tokio::test]
async fn test_mqtt5_and_mqtt311_auth_reason_codes() {
    let mut acl = AclEngine::new(false);
    acl.create_user(
        "alice",
        "correct_horse_battery_staple",
        wolf_mqtt::auth::UserRole::Member,
    );

    let server = BrokerServer::bind("127.0.0.1:0")
        .await
        .expect("Broker bind failed")
        .with_acl(acl);
    let server_addr = server.local_addr().expect("Failed to get local addr");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. MQTT 5.0 connection with wrong password -> must receive Reason Code 0x86 (Bad User/Password)
    let mut v5_stream = TcpStream::connect(server_addr)
        .await
        .expect("v5 connect failed");
    send_packet(
        &mut v5_stream,
        MqttPacket::Connect(
            ConnectPacket::new("v5_client")
                .with_credentials("alice", Bytes::from_static(b"wrong_password")),
        ),
    )
    .await;

    let v5_ack = timeout(Duration::from_secs(2), read_packet(&mut v5_stream))
        .await
        .expect("v5 ConnAck timeout");
    assert_eq!(
        v5_ack,
        MqttPacket::ConnAck {
            session_present: false,
            reason_code: 0x86, // MQTT 5.0 Reason Code for Bad User Name or Password
        }
    );

    // 2. MQTT 3.1.1 connection with wrong password -> must receive Return Code 0x05 (Not authorized)
    let mut v3_stream = TcpStream::connect(server_addr)
        .await
        .expect("v3 connect failed");
    let mut v3_conn = ConnectPacket::new("v3_client")
        .with_credentials("alice", Bytes::from_static(b"wrong_password"));
    v3_conn.version = ProtocolVersion::V311;

    send_packet(&mut v3_stream, MqttPacket::Connect(v3_conn)).await;

    let v3_ack = timeout(Duration::from_secs(2), read_packet(&mut v3_stream))
        .await
        .expect("v3 ConnAck timeout");
    assert_eq!(
        v3_ack,
        MqttPacket::ConnAck {
            session_present: false,
            reason_code: 0x05, // MQTT 3.1.1 Return Code for Not Authorized
        }
    );
}

#[tokio::test]
async fn test_cross_protocol_v3_and_v5_interoperability() {
    let server = BrokerServer::bind("127.0.0.1:0")
        .await
        .expect("Broker bind failed");
    let server_addr = server.local_addr().expect("Failed to get local addr");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Subscriber 1: MQTT v3.1.1
    let mut v3_sub = TcpStream::connect(server_addr).await.unwrap();
    send_packet(
        &mut v3_sub,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V311,
            client_id: "legacy_v3_sub".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;
    assert!(matches!(
        read_packet(&mut v3_sub).await,
        MqttPacket::ConnAck { .. }
    ));
    send_packet(
        &mut v3_sub,
        MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("bridge/interop/#".into(), QoS::AtMostOnce)],
        },
    )
    .await;
    assert!(matches!(
        read_packet(&mut v3_sub).await,
        MqttPacket::SubAck { .. }
    ));

    // Subscriber 2: MQTT v5.0
    let mut v5_sub = TcpStream::connect(server_addr).await.unwrap();
    send_packet(
        &mut v5_sub,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "modern_v5_sub".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;
    assert!(matches!(
        read_packet(&mut v5_sub).await,
        MqttPacket::ConnAck { .. }
    ));
    send_packet(
        &mut v5_sub,
        MqttPacket::Subscribe {
            packet_id: 2,
            topics: vec![("bridge/interop/#".into(), QoS::AtMostOnce)],
        },
    )
    .await;
    assert!(matches!(
        read_packet(&mut v5_sub).await,
        MqttPacket::SubAck { .. }
    ));

    // Publisher: MQTT v5.0 sends message
    let mut v5_pub = TcpStream::connect(server_addr).await.unwrap();
    send_packet(
        &mut v5_pub,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "modern_v5_pub".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;
    assert!(matches!(
        read_packet(&mut v5_pub).await,
        MqttPacket::ConnAck { .. }
    ));

    send_packet(
        &mut v5_pub,
        MqttPacket::Publish(PublishPacket {
            topic: "bridge/interop/payload_from_v5".into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"HELLO_FROM_MQTT_5"),
        }),
    )
    .await;

    // Both v3 and v5 subscribers receive the message!
    let msg_v3 = timeout(Duration::from_secs(2), read_packet(&mut v3_sub))
        .await
        .expect("v3 sub timeout");
    let msg_v5 = timeout(Duration::from_secs(2), read_packet(&mut v5_sub))
        .await
        .expect("v5 sub timeout");

    if let MqttPacket::Publish(p) = msg_v3 {
        assert_eq!(&p.payload[..], b"HELLO_FROM_MQTT_5");
    } else {
        panic!("Expected Publish on v3 sub");
    }

    if let MqttPacket::Publish(p) = msg_v5 {
        assert_eq!(&p.payload[..], b"HELLO_FROM_MQTT_5");
    } else {
        panic!("Expected Publish on v5 sub");
    }
}
