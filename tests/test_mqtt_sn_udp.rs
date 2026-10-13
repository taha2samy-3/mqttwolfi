use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use wolf_mqtt::auth::AclEngine;
use wolf_mqtt::config::MqttSnListenerConfig;
use wolf_mqtt::protocol::sn::{SnPacket, TopicIdType};
use wolf_mqtt::protocol::{
    ConnectPacket, MqttPacket, ProtocolVersion, PublishPacket, QoS,
};
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
        port: 0, // dynamic port
        gateway_id: 1,
        advertise_interval_sec: 0,
        predefined_topics: predefined,
    };

    let bind_addr = format!("{}:{}", config.bind_address, config.port);
    let socket = Arc::new(UdpSocket::bind(&bind_addr).await.unwrap());
    let local_addr = socket.local_addr().unwrap();

    let server_config = config.clone();
    let server_context = (*context).clone();

    // Spawn server using the bound socket port
    tokio::spawn(async move {
        let sn_server = MqttSnServer::new(
            MqttSnListenerConfig {
                port: local_addr.port(),
                ..server_config
            },
            server_context,
        );
        let _ = sn_server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (local_addr, context)
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
    let mut recv_buf = [0u8; 256];
    let (len, _) = client_sock.recv_from(&mut recv_buf).await.unwrap();
    let mut slice = &recv_buf[..len];
    let resp = SnPacket::decode(&mut slice).unwrap();
    assert_eq!(resp, SnPacket::ConnAck { return_code: 0x00 });

    // 2. Send PINGREQ
    buf.clear();
    SnPacket::PingReq { client_id: None }.encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    let (len, _) = client_sock.recv_from(&mut recv_buf).await.unwrap();
    let mut slice = &recv_buf[..len];
    let ping_resp = SnPacket::decode(&mut slice).unwrap();
    assert_eq!(ping_resp, SnPacket::PingResp);

    // 3. Send DISCONNECT
    buf.clear();
    SnPacket::Disconnect { duration: None }.encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    let (len, _) = client_sock.recv_from(&mut recv_buf).await.unwrap();
    let mut slice = &recv_buf[..len];
    let disc_resp = SnPacket::decode(&mut slice).unwrap();
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

    let mut recv_buf = [0u8; 256];
    let _ = client_sock.recv_from(&mut recv_buf).await.unwrap();

    // Register Topic
    buf.clear();
    SnPacket::Register {
        topic_id: 0,
        msg_id: 1,
        topic_name: "custom/sensor/data".into(),
    }
    .encode(&mut buf);
    client_sock.send_to(&buf, server_addr).await.unwrap();

    let (len, _) = client_sock.recv_from(&mut recv_buf).await.unwrap();
    let mut slice = &recv_buf[..len];
    let regack = SnPacket::decode(&mut slice).unwrap();

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

    let (len, _) = client_sock.recv_from(&mut recv_buf).await.unwrap();
    let mut slice = &recv_buf[..len];
    let puback = SnPacket::decode(&mut slice).unwrap();
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

    // In MQTT-SN, QoS -1 with Predefined Topic ID does NOT require CONNECT!
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

    let udp_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let udp_addr = udp_sock.local_addr().unwrap();
    let sn_server = MqttSnServer::new(
        MqttSnListenerConfig {
            port: udp_addr.port(),
            ..sn_config
        },
        (*shared_context).clone(),
    );
    tokio::spawn(async move {
        let _ = sn_server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 3. Connect TCP client (Ground Station) and subscribe to "uav/drone_01/telemetry/gps"
    let mut tcp_stream = TcpStream::connect(tcp_addr).await.unwrap();
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

    let mut read_buf = [0u8; 1024];
    let _ = tcp_stream.read(&mut read_buf).await.unwrap(); // CONNACK

    // Subscribe to UAV telemetry
    tcp_buf.clear();
    let sub_pkt = MqttPacket::Subscribe {
        packet_id: 10,
        topics: vec![("uav/drone_01/telemetry/gps".into(), QoS::AtLeastOnce)],
    };
    sub_pkt.encode(&mut tcp_buf).unwrap();
    tcp_stream.write_all(&tcp_buf).await.unwrap();
    let _ = tcp_stream.read(&mut read_buf).await.unwrap(); // SUBACK

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

    // 5. Verify Ground Station receives message over TCP in real time!
    let n = tcp_stream.read(&mut read_buf).await.unwrap();
    let mut slice = &read_buf[..n];
    let received = MqttPacket::decode(&mut slice).unwrap();

    if let MqttPacket::Publish(p) = received {
        assert_eq!(p.topic, "uav/drone_01/telemetry/gps");
        assert_eq!(p.payload, Bytes::from_static(b"AIRBORNE:ALTITUDE=120M"));
    } else {
        panic!("Expected PUBLISH on TCP stream, got {:?}", received);
    }
}
