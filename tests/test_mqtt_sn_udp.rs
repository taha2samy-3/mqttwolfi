use bytes::{Buf, Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use wolf_mqtt::auth::AclEngine;
use wolf_mqtt::config::MqttSnListenerConfig;
use wolf_mqtt::protocol::sn::{SnPacket, TopicIdType};
use wolf_mqtt::protocol::{ConnectPacket, MqttPacket, ProtocolVersion, PublishPacket, QoS};
use wolf_mqtt::server::{BrokerContext, BrokerServer};
use wolf_mqtt::server_sn::MqttSnServer;

async fn spawn_test_sn_server() -> (SocketAddr, Arc<BrokerContext>) {
    let acl = Arc::new(AclEngine::new(true));
    let context = Arc::new(BrokerContext::new(acl));

    let mut predefined = HashMap::new();
    predefined.insert("1".into(), "uav/drone_01/telemetry/gps".into());
    predefined.insert("2".into(), "uav/drone_01/commands".into());

    let config = MqttSnListenerConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        port: 0, // OS assigns an ephemeral port
        gateway_id: 1,
        advertise_interval_sec: 0,
        predefined_topics: predefined,
    };

    let server_context = (*context).clone();
    let sn_server = MqttSnServer::bind(config, server_context).await.unwrap();
    let local_addr = sn_server.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = sn_server.run().await;
    });

    (local_addr, context)
}

async fn recv_sn_packet(sock: &UdpSocket) -> SnPacket {
    let mut buf = [0u8; 1024];
    let (n, _) = timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .expect("Timeout waiting for UDP packet")
        .expect("Failed to recv from UDP socket");
    let mut slice = &buf[..n];
    SnPacket::decode(&mut slice).expect("Failed to decode SnPacket")
}

async fn read_mqtt_packet(stream: &mut TcpStream, buf: &mut BytesMut) -> MqttPacket {
    loop {
        if !buf.is_empty() {
            let mut slice = &buf[..];
            if let Ok(pkt) = MqttPacket::decode(&mut slice) {
                let consumed = buf.len() - slice.len();
                buf.advance(consumed);
                return pkt;
            }
        }
        let n = timeout(Duration::from_secs(3), stream.read_buf(buf))
            .await
            .expect("Timeout waiting for TCP MQTT packet")
            .expect("Socket read failed");
        assert!(n > 0, "Unexpected EOF while reading TCP stream");
    }
}

#[tokio::test]
async fn test_mqtt_sn_connect_ping_disconnect() {
    let (server_addr, _context) = spawn_test_sn_server().await;
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 1. Send CONNECT
    let connect = SnPacket::Connect {
        will: false,
        clean_session: true,
        duration: 30,
        client_id: "drone-test-01".into(),
    };
    let mut buf = BytesMut::new();
    connect.encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    // Receive CONNACK
    let resp = recv_sn_packet(&client_sock).await;
    assert_eq!(resp, SnPacket::ConnAck { return_code: 0x00 });

    // 2. Send PINGREQ
    buf.clear();
    SnPacket::PingReq { client_id: None }.encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    let ping_resp = recv_sn_packet(&client_sock).await;
    assert_eq!(ping_resp, SnPacket::PingResp);

    // 3. Send DISCONNECT
    buf.clear();
    SnPacket::Disconnect { duration: None }.encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    let disc_resp = recv_sn_packet(&client_sock).await;
    assert_eq!(disc_resp, SnPacket::Disconnect { duration: None });
}

#[tokio::test]
async fn test_mqtt_sn_register_and_publish_qos1() {
    let (server_addr, _context) = spawn_test_sn_server().await;
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Connect first
    let mut buf = BytesMut::new();
    SnPacket::Connect {
        will: false,
        clean_session: true,
        duration: 60,
        client_id: "drone-reg-test".into(),
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    let connack = recv_sn_packet(&client_sock).await;
    assert_eq!(connack, SnPacket::ConnAck { return_code: 0x00 });

    // Register Topic
    buf.clear();
    SnPacket::Register {
        topic_id: 0,
        msg_id: 1,
        topic_name: "custom/sensor/data".into(),
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    let regack = recv_sn_packet(&client_sock).await;
    let assigned_id = match regack {
        SnPacket::RegAck {
            topic_id,
            msg_id,
            return_code,
        } => {
            assert_eq!(msg_id, 1);
            assert_eq!(return_code, 0x00);
            assert!(topic_id >= 100);
            topic_id
        }
        other => panic!("Expected RegAck, got {:?}", other),
    };

    // Publish QoS 1 on newly registered topic
    buf.clear();
    SnPacket::Publish {
        dup: false,
        qos: 1,
        retain: false,
        topic_id_type: TopicIdType::Normal,
        topic_id: assigned_id,
        msg_id: 2,
        data: Bytes::from_static(b"TEMPERATURE:25.4C"),
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    let puback = recv_sn_packet(&client_sock).await;
    assert_eq!(
        puback,
        SnPacket::PubAck {
            topic_id: assigned_id,
            msg_id: 2,
            return_code: 0x00
        }
    );
}

#[tokio::test]
async fn test_mqtt_sn_predefined_topic_and_qos_minus1() {
    let (server_addr, _context) = spawn_test_sn_server().await;
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // In MQTT-SN, QoS -1 with Predefined Topic ID does NOT require CONNECT
    let mut buf = BytesMut::new();
    SnPacket::Publish {
        dup: false,
        qos: -1,
        retain: false,
        topic_id_type: TopicIdType::Predefined,
        topic_id: 1, // Predefined 1 -> "uav/drone_01/telemetry/gps"
        msg_id: 0,
        data: Bytes::from_static(b"GPS:lat=30.0444,lon=31.2357"),
    }
    .encode(&mut buf);

    // Fire-and-forget over UDP
    client_sock.send_to(&buf, server_addr).await.unwrap();
}

#[tokio::test]
async fn test_cross_protocol_sn_udp_to_tcp_delivery() {
    let acl = Arc::new(AclEngine::new(true));
    let shared_context = Arc::new(BrokerContext::new(acl));

    // 1. Start TCP listener
    let tcp_server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_server.local_addr().unwrap();
    let tcp_server = tcp_server.with_context((*shared_context).clone());
    tokio::spawn(async move {
        let _ = tcp_server.run().await;
    });

    // 2. Start UDP MQTT-SN listener sharing the exact same context
    let mut predefined = HashMap::new();
    predefined.insert("1".into(), "uav/drone_01/telemetry/gps".into());

    let sn_config = MqttSnListenerConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        port: 0,
        gateway_id: 1,
        advertise_interval_sec: 0,
        predefined_topics: predefined,
    };

    let sn_server = MqttSnServer::bind(sn_config, (*shared_context).clone())
        .await
        .unwrap();
    let udp_addr = sn_server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = sn_server.run().await;
    });

    // 3. Connect TCP client (Ground Station) and subscribe to "uav/drone_01/telemetry/gps"
    let mut tcp_stream = TcpStream::connect(tcp_addr).await.unwrap();
    let mut tcp_read_buf = BytesMut::with_capacity(4096);

    let conn_pkt = MqttPacket::Connect(ConnectPacket {
        version: ProtocolVersion::V500,
        client_id: "gcs-ground-station".into(),
        clean_start: true,
        keep_alive_sec: 30,
        will: None,
        username: None,
        password: None,
    });
    let mut tcp_buf = BytesMut::new();
    conn_pkt.encode(&mut tcp_buf).unwrap();
    tcp_stream.write_all(&tcp_buf).await.unwrap();

    let connack = read_mqtt_packet(&mut tcp_stream, &mut tcp_read_buf).await;
    assert!(matches!(connack, MqttPacket::ConnAck { .. }));

    // Subscribe to UAV telemetry
    tcp_buf.clear();
    let sub_pkt = MqttPacket::Subscribe {
        packet_id: 10,
        topics: vec![("uav/drone_01/telemetry/gps".into(), QoS::AtLeastOnce)],
    };
    sub_pkt.encode(&mut tcp_buf).unwrap();
    tcp_stream.write_all(&tcp_buf).await.unwrap();

    let suback = read_mqtt_packet(&mut tcp_stream, &mut tcp_read_buf).await;
    assert!(matches!(suback, MqttPacket::SubAck { .. }));

    // 4. Drone client sends UDP packet (MQTT-SN) with topic_id = 1
    let drone_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut sn_buf = BytesMut::new();
    SnPacket::Publish {
        dup: false,
        qos: 1,
        retain: false,
        topic_id_type: TopicIdType::Predefined,
        topic_id: 1, // "uav/drone_01/telemetry/gps"
        msg_id: 99,
        data: Bytes::from_static(b"AIRBORNE:ALTITUDE=120M"),
    }
    .encode(&mut sn_buf);
    drone_sock.send_to(&sn_buf, udp_addr).await.unwrap();

    // 5. Verify Ground Station receives message over TCP in real time
    let received = read_mqtt_packet(&mut tcp_stream, &mut tcp_read_buf).await;
    if let MqttPacket::Publish(p) = received {
        assert_eq!(p.topic, "uav/drone_01/telemetry/gps");
        assert_eq!(p.payload, Bytes::from_static(b"AIRBORNE:ALTITUDE=120M"));
    } else {
        panic!("Expected PUBLISH on TCP stream, got {:?}", received);
    }
}

#[tokio::test]
async fn test_cross_protocol_tcp_to_sn_udp_delivery() {
    let acl = Arc::new(AclEngine::new(true));
    let shared_context = Arc::new(BrokerContext::new(acl));

    // 1. Start TCP listener
    let tcp_server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp_server.local_addr().unwrap();
    let tcp_server = tcp_server.with_context((*shared_context).clone());
    tokio::spawn(async move {
        let _ = tcp_server.run().await;
    });

    // 2. Start UDP MQTT-SN listener sharing the exact same context
    let mut predefined = HashMap::new();
    predefined.insert("2".into(), "uav/drone_01/commands".into());

    let sn_config = MqttSnListenerConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        port: 0,
        gateway_id: 1,
        advertise_interval_sec: 0,
        predefined_topics: predefined,
    };

    let sn_server = MqttSnServer::bind(sn_config, (*shared_context).clone())
        .await
        .unwrap();
    let udp_addr = sn_server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = sn_server.run().await;
    });

    // 3. Drone client connects and subscribes to predefined topic 2 ("uav/drone_01/commands")
    let drone_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut sn_buf = BytesMut::new();
    SnPacket::Connect {
        will: false,
        clean_session: true,
        duration: 60,
        client_id: "drone-sub-01".into(),
    }
    .encode(&mut sn_buf);
    drone_sock.send_to(&sn_buf, udp_addr).await.unwrap();

    let connack = recv_sn_packet(&drone_sock).await;
    assert_eq!(connack, SnPacket::ConnAck { return_code: 0x00 });

    sn_buf.clear();
    SnPacket::Subscribe {
        dup: false,
        qos: 1,
        topic_id_type: TopicIdType::Predefined,
        topic_id: 2,
        topic_name: None,
        msg_id: 10,
    }
    .encode(&mut sn_buf);
    drone_sock.send_to(&sn_buf, udp_addr).await.unwrap();

    let suback = recv_sn_packet(&drone_sock).await;
    assert_eq!(
        suback,
        SnPacket::SubAck {
            qos: 1,
            topic_id: 2,
            msg_id: 10,
            return_code: 0x00,
        }
    );

    // 4. Ground Station connects over TCP and publishes a command to "uav/drone_01/commands"
    let mut tcp_stream = TcpStream::connect(tcp_addr).await.unwrap();
    let mut tcp_read_buf = BytesMut::with_capacity(4096);

    let conn_pkt = MqttPacket::Connect(ConnectPacket {
        version: ProtocolVersion::V500,
        client_id: "gcs-command-center".into(),
        clean_start: true,
        keep_alive_sec: 30,
        will: None,
        username: None,
        password: None,
    });
    let mut tcp_buf = BytesMut::new();
    conn_pkt.encode(&mut tcp_buf).unwrap();
    tcp_stream.write_all(&tcp_buf).await.unwrap();
    let _ = read_mqtt_packet(&mut tcp_stream, &mut tcp_read_buf).await;

    // Send command
    tcp_buf.clear();
    let cmd_pub = MqttPacket::Publish(PublishPacket {
        topic: "uav/drone_01/commands".into(),
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
        packet_id: Some(42),
        payload: Bytes::from_static(b"COMMAND:RETURN_TO_LAUNCH"),
    });
    cmd_pub.encode(&mut tcp_buf).unwrap();
    tcp_stream.write_all(&tcp_buf).await.unwrap();

    // 5. Drone client receives SnPacket::Publish over UDP!
    let received_sn = recv_sn_packet(&drone_sock).await;
    match received_sn {
        SnPacket::Publish {
            topic_id,
            topic_id_type,
            data,
            ..
        } => {
            assert_eq!(topic_id, 2);
            assert_eq!(topic_id_type, TopicIdType::Predefined);
            assert_eq!(data, Bytes::from_static(b"COMMAND:RETURN_TO_LAUNCH"));
        }
        other => panic!("Expected SnPacket::Publish, got {:?}", other),
    }
}

#[tokio::test]
async fn test_mqtt_sn_lwt_handshake_flow() {
    let (server_addr, _context) = spawn_test_sn_server().await;
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 1. Connect with will = true
    let mut buf = BytesMut::new();
    SnPacket::Connect {
        will: true,
        clean_session: true,
        duration: 30,
        client_id: "drone-lwt-client".into(),
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    // 2. Gateway MUST prompt with WillTopicReq
    let resp1 = recv_sn_packet(&client_sock).await;
    assert_eq!(resp1, SnPacket::WillTopicReq);

    // 3. Client responds with WillTopic
    buf.clear();
    SnPacket::WillTopic {
        qos: 1,
        retain: false,
        will_topic: "uav/drone_01/status/lost".into(),
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    // 4. Gateway prompts with WillMsgReq
    let resp2 = recv_sn_packet(&client_sock).await;
    assert_eq!(resp2, SnPacket::WillMsgReq);

    // 5. Client responds with WillMsg
    buf.clear();
    SnPacket::WillMsg {
        will_msg: Bytes::from_static(b"SIGNAL_LOST_CRASH_DETECTED"),
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    // 6. Gateway now completes handshake with ConnAck!
    let resp3 = recv_sn_packet(&client_sock).await;
    assert_eq!(resp3, SnPacket::ConnAck { return_code: 0x00 });
}

#[tokio::test]
async fn test_mqtt_sn_unsubscribe_flow() {
    let (server_addr, _context) = spawn_test_sn_server().await;
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Connect first
    let mut buf = BytesMut::new();
    SnPacket::Connect {
        will: false,
        clean_session: true,
        duration: 60,
        client_id: "unsub-drone".into(),
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();
    let _ = recv_sn_packet(&client_sock).await; // ConnAck

    // Subscribe
    buf.clear();
    SnPacket::Subscribe {
        dup: false,
        qos: 1,
        topic_id_type: TopicIdType::Predefined,
        topic_id: 1,
        topic_name: None,
        msg_id: 20,
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();
    let suback = recv_sn_packet(&client_sock).await;
    assert!(matches!(
        suback,
        SnPacket::SubAck {
            return_code: 0x00,
            ..
        }
    ));

    // Unsubscribe
    buf.clear();
    SnPacket::Unsubscribe {
        topic_id_type: TopicIdType::Predefined,
        msg_id: 21,
        topic_id: 1,
        topic_name: None,
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    // Verify UnsubAck with msg_id 21
    let unsuback = recv_sn_packet(&client_sock).await;
    assert_eq!(unsuback, SnPacket::UnsubAck { msg_id: 21 });
}

#[tokio::test]
async fn test_mqtt_sn_qos2_handshake_flow() {
    let (server_addr, _context) = spawn_test_sn_server().await;
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 1. Send Publish with QoS 2
    let mut buf = BytesMut::new();
    SnPacket::Publish {
        dup: false,
        qos: 2,
        retain: false,
        topic_id_type: TopicIdType::Predefined,
        topic_id: 1,
        msg_id: 77,
        data: Bytes::from_static(b"CRITICAL_WAYPOINT_CONFIRMED"),
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    // 2. Gateway MUST reply with PubRec
    let pubrec = recv_sn_packet(&client_sock).await;
    assert_eq!(pubrec, SnPacket::PubRec { msg_id: 77 });

    // 3. Client sends PubRel
    buf.clear();
    SnPacket::PubRel { msg_id: 77 }.encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    // 4. Gateway completes with PubComp
    let pubcomp = recv_sn_packet(&client_sock).await;
    assert_eq!(pubcomp, SnPacket::PubComp { msg_id: 77 });
}

#[tokio::test]
async fn test_mqtt_sn_sleeping_client_lifecycle() {
    let (server_addr, _context) = spawn_test_sn_server().await;
    let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 1. Connect
    let mut buf = BytesMut::new();
    SnPacket::Connect {
        will: false,
        clean_session: true,
        duration: 100,
        client_id: "low-power-sensor-99".into(),
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();
    let _ = recv_sn_packet(&client_sock).await; // ConnAck

    // 2. Client enters sleep state with duration = 300s
    buf.clear();
    SnPacket::Disconnect {
        duration: Some(300),
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    // Gateway acknowledges with Disconnect (without duration)
    let disc_ack = recv_sn_packet(&client_sock).await;
    assert_eq!(disc_ack, SnPacket::Disconnect { duration: None });

    // 3. Client wakes up and sends PingReq with its client_id
    buf.clear();
    SnPacket::PingReq {
        client_id: Some("low-power-sensor-99".into()),
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    // Gateway responds with PingResp
    let ping_resp = recv_sn_packet(&client_sock).await;
    assert_eq!(ping_resp, SnPacket::PingResp);
}

#[tokio::test]
async fn test_mqtt_sn_sleeping_client_buffered_messages() {
    let (server_addr, _context) = spawn_test_sn_server().await;
    let sleepy_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let publisher_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 1. Sleepy client connects
    let mut buf = BytesMut::new();
    SnPacket::Connect {
        will: false,
        clean_session: true,
        duration: 300,
        client_id: "sleepy-uav-1".into(),
    }
    .encode(&mut buf);
    sleepy_sock.send_to(&buf, server_addr).await.unwrap();
    let _ = recv_sn_packet(&sleepy_sock).await; // ConnAck

    // 2. Sleepy client subscribes to "uav/mission"
    buf.clear();
    SnPacket::Subscribe {
        dup: false,
        qos: 0,
        topic_id_type: TopicIdType::Normal,
        msg_id: 10,
        topic_id: 0,
        topic_name: Some("uav/mission".into()),
    }
    .encode(&mut buf);
    sleepy_sock.send_to(&buf, server_addr).await.unwrap();
    let suback = recv_sn_packet(&sleepy_sock).await;
    let assigned_tid = match suback {
        SnPacket::SubAck { topic_id, .. } => topic_id,
        other => panic!("Expected SubAck, got {:?}", other),
    };

    // 3. Sleepy client enters Asleep state
    buf.clear();
    SnPacket::Disconnect {
        duration: Some(300),
    }
    .encode(&mut buf);
    sleepy_sock.send_to(&buf, server_addr).await.unwrap();
    let disc_ack = recv_sn_packet(&sleepy_sock).await;
    assert_eq!(disc_ack, SnPacket::Disconnect { duration: None });

    // 4. Publisher connects and publishes to "uav/mission" while sleepy is asleep
    buf.clear();
    SnPacket::Connect {
        will: false,
        clean_session: true,
        duration: 60,
        client_id: "base-station-pub".into(),
    }
    .encode(&mut buf);
    publisher_sock.send_to(&buf, server_addr).await.unwrap();
    let _ = recv_sn_packet(&publisher_sock).await; // ConnAck

    buf.clear();
    SnPacket::Register {
        topic_id: 0,
        msg_id: 1,
        topic_name: "uav/mission".into(),
    }
    .encode(&mut buf);
    publisher_sock.send_to(&buf, server_addr).await.unwrap();
    let regack = recv_sn_packet(&publisher_sock).await;
    let pub_tid = match regack {
        SnPacket::RegAck { topic_id, .. } => topic_id,
        other => panic!("Expected RegAck, got {:?}", other),
    };

    buf.clear();
    SnPacket::Publish {
        dup: false,
        qos: 0,
        retain: false,
        topic_id_type: TopicIdType::Normal,
        topic_id: pub_tid,
        msg_id: 0,
        data: Bytes::from_static(b"COMMAND:RETURN_BASE"),
    }
    .encode(&mut buf);
    publisher_sock.send_to(&buf, server_addr).await.unwrap();

    // Small delay to ensure message was routed and buffered
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 5. Sleepy client wakes up with PingReq { client_id }
    buf.clear();
    SnPacket::PingReq {
        client_id: Some("sleepy-uav-1".into()),
    }
    .encode(&mut buf);
    sleepy_sock.send_to(&buf, server_addr).await.unwrap();

    // Sleepy client MUST receive the buffered Publish first!
    let buffered_pub = recv_sn_packet(&sleepy_sock).await;
    match buffered_pub {
        SnPacket::Publish { topic_id, data, .. } => {
            assert_eq!(topic_id, assigned_tid);
            assert_eq!(data, Bytes::from_static(b"COMMAND:RETURN_BASE"));
        }
        other => panic!("Expected buffered Publish, got {:?}", other),
    }

    // Sleepy client receives PingResp to conclude waking transaction
    let ping_resp = recv_sn_packet(&sleepy_sock).await;
    assert_eq!(ping_resp, SnPacket::PingResp);
}

#[tokio::test]
async fn test_mqtt_sn_keepalive_timeout_and_lwt_broadcast() {
    let (server_addr, _context) = spawn_test_sn_server().await;
    let dying_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let monitor_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 1. Monitor connects and subscribes to "telemetry/drone_loss"
    let mut buf = BytesMut::new();
    SnPacket::Connect {
        will: false,
        clean_session: true,
        duration: 100,
        client_id: "fleet-monitor".into(),
    }
    .encode(&mut buf);
    monitor_sock.send_to(&buf, server_addr).await.unwrap();
    let _ = recv_sn_packet(&monitor_sock).await; // ConnAck

    buf.clear();
    SnPacket::Subscribe {
        dup: false,
        qos: 0,
        topic_id_type: TopicIdType::Normal,
        msg_id: 1,
        topic_id: 0,
        topic_name: Some("telemetry/drone_loss".into()),
    }
    .encode(&mut buf);
    monitor_sock.send_to(&buf, server_addr).await.unwrap();
    let suback = recv_sn_packet(&monitor_sock).await;
    let monitor_tid = match suback {
        SnPacket::SubAck { topic_id, .. } => topic_id,
        other => panic!("Expected SubAck, got {:?}", other),
    };

    // 2. Dying client connects with duration = 1s and sets Will
    buf.clear();
    SnPacket::Connect {
        will: true,
        clean_session: true,
        duration: 1, // 1 second keepalive!
        client_id: "dying-drone-404".into(),
    }
    .encode(&mut buf);
    dying_sock.send_to(&buf, server_addr).await.unwrap();

    // LWT handshake
    let req1 = recv_sn_packet(&dying_sock).await;
    assert_eq!(req1, SnPacket::WillTopicReq);

    buf.clear();
    SnPacket::WillTopic {
        qos: 0,
        retain: false,
        will_topic: "telemetry/drone_loss".into(),
    }
    .encode(&mut buf);
    dying_sock.send_to(&buf, server_addr).await.unwrap();

    let req2 = recv_sn_packet(&dying_sock).await;
    assert_eq!(req2, SnPacket::WillMsgReq);

    buf.clear();
    SnPacket::WillMsg {
        will_msg: Bytes::from_static(b"DRONE_SIGNAL_LOST_MAYDAY"),
    }
    .encode(&mut buf);
    dying_sock.send_to(&buf, server_addr).await.unwrap();

    let connack = recv_sn_packet(&dying_sock).await;
    assert_eq!(connack, SnPacket::ConnAck { return_code: 0x00 });

    // 3. Dying client goes silent. Reaper detects timeout after 1.5 * 1s = 1.5s
    // Monitor should receive the LWT PUBLISH!
    let lwt_received = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        recv_sn_packet(&monitor_sock),
    )
    .await
    .expect("Timed out waiting for LWT publish from reaper");

    match lwt_received {
        SnPacket::Publish { topic_id, data, .. } => {
            assert_eq!(topic_id, monitor_tid);
            assert_eq!(data, Bytes::from_static(b"DRONE_SIGNAL_LOST_MAYDAY"));
        }
        other => panic!("Expected LWT Publish, got {:?}", other),
    }
}
