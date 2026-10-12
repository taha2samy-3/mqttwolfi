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
async fn test_lwt_triggered_on_abrupt_disconnect() {
    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 1. Observer Client connects and subscribes to "edge/alerts/#"
    let mut observer_stream = TcpStream::connect(addr).await.unwrap();
    send_packet(
        &mut observer_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "observer_client".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;

    let _ = timeout(Duration::from_secs(2), read_packet(&mut observer_stream))
        .await
        .unwrap();

    send_packet(
        &mut observer_stream,
        MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("edge/alerts/#".into(), QoS::AtMostOnce)],
        },
    )
    .await;

    let _ = timeout(Duration::from_secs(2), read_packet(&mut observer_stream))
        .await
        .unwrap();

    // 2. Edge Device connects with a Last Will and Testament configured
    {
        let mut edge_stream = TcpStream::connect(addr).await.unwrap();
        let will = PublishPacket {
            topic: "edge/alerts/device-77".into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"STATUS_LOST_POWER"),
        };

        send_packet(
            &mut edge_stream,
            MqttPacket::Connect(ConnectPacket {
                version: ProtocolVersion::V500,
                client_id: "edge-device-77".into(),
                clean_start: true,
                keep_alive_sec: 60,
                will: Some(will),
                username: None,
                password: None,
            }),
        )
        .await;

        let _ = timeout(Duration::from_secs(2), read_packet(&mut edge_stream))
            .await
            .unwrap();

        // Edge device unexpectedly dies (drops TCP stream without MqttPacket::Disconnect)
        drop(edge_stream);
    }

    // 3. Observer MUST receive the Last Will & Testament message from the broker!
    let lwt_packet = timeout(Duration::from_secs(2), read_packet(&mut observer_stream))
        .await
        .expect("Observer should have received LWT message");

    if let MqttPacket::Publish(pub_pkt) = lwt_packet {
        assert_eq!(pub_pkt.topic, "edge/alerts/device-77");
        assert_eq!(pub_pkt.payload, Bytes::from_static(b"STATUS_LOST_POWER"));
    } else {
        panic!("Expected Publish packet for LWT, got {:?}", lwt_packet);
    }
}

#[tokio::test]
async fn test_lwt_cancelled_on_clean_disconnect() {
    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // 1. Observer Client connects and subscribes to "nodes/status/#"
    let mut observer_stream = TcpStream::connect(addr).await.unwrap();
    send_packet(
        &mut observer_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "status_monitor".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
            username: None,
            password: None,
        }),
    )
    .await;

    let _ = timeout(Duration::from_secs(2), read_packet(&mut observer_stream))
        .await
        .unwrap();

    send_packet(
        &mut observer_stream,
        MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("nodes/status/#".into(), QoS::AtMostOnce)],
        },
    )
    .await;

    let _ = timeout(Duration::from_secs(2), read_packet(&mut observer_stream))
        .await
        .unwrap();

    // 2. Node connects with Will configured
    {
        let mut node_stream = TcpStream::connect(addr).await.unwrap();
        let will = PublishPacket {
            topic: "nodes/status/node-01".into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"CRITICAL_FAILURE"),
        };

        send_packet(
            &mut node_stream,
            MqttPacket::Connect(ConnectPacket {
                version: ProtocolVersion::V500,
                client_id: "node-01".into(),
                clean_start: true,
                keep_alive_sec: 60,
                will: Some(will),
                username: None,
                password: None,
            }),
        )
        .await;

        let _ = timeout(Duration::from_secs(2), read_packet(&mut node_stream))
            .await
            .unwrap();

        // Node cleanly disconnects by sending DISCONNECT packet first!
        send_packet(&mut node_stream, MqttPacket::Disconnect).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(node_stream);
    }

    // 3. Observer MUST NOT receive any LWT packet
    let timeout_res = timeout(
        Duration::from_millis(300),
        read_packet(&mut observer_stream),
    )
    .await;
    assert!(
        timeout_res.is_err(),
        "LWT must be cancelled on clean DISCONNECT; no packet should arrive"
    );
}
