use bytes::{Bytes, BytesMut};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
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
        let n = stream.read_buf(&mut buf).await.expect("Read must succeed");
        assert!(n > 0, "Unexpected EOF while reading packet");
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
async fn test_e2e_real_tcp_pub_sub_exchange() {
    // 1. Start live broker on ephemeral port
    let server = BrokerServer::bind("127.0.0.1:0")
        .await
        .expect("Broker bind failed");
    let server_addr = server.local_addr().expect("Failed to get local addr");

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // 2. Client A connects as Subscriber
    let mut sub_stream = TcpStream::connect(server_addr)
        .await
        .expect("Subscriber connection failed");

    send_packet(
        &mut sub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "e2e_sub_client".into(),
            clean_start: true,
            keep_alive_sec: 60,
        }),
    )
    .await;

    let connack = timeout(Duration::from_secs(2), read_packet(&mut sub_stream))
        .await
        .expect("ConnAck timeout");
    assert_eq!(
        connack,
        MqttPacket::ConnAck {
            session_present: false,
            reason_code: 0x00,
        }
    );

    // Subscribe to "factory/+/temperature"
    send_packet(
        &mut sub_stream,
        MqttPacket::Subscribe {
            packet_id: 1,
            topics: vec![("factory/+/temperature".into(), QoS::AtMostOnce)],
        },
    )
    .await;

    let suback = timeout(Duration::from_secs(2), read_packet(&mut sub_stream))
        .await
        .expect("SubAck timeout");
    assert_eq!(
        suback,
        MqttPacket::SubAck {
            packet_id: 1,
            return_codes: vec![0x00],
        }
    );

    // 3. Client B connects as Publisher
    let mut pub_stream = TcpStream::connect(server_addr)
        .await
        .expect("Publisher connection failed");

    send_packet(
        &mut pub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "e2e_pub_client".into(),
            clean_start: true,
            keep_alive_sec: 60,
        }),
    )
    .await;

    let pub_connack = timeout(Duration::from_secs(2), read_packet(&mut pub_stream))
        .await
        .expect("Publisher ConnAck timeout");
    assert_eq!(
        pub_connack,
        MqttPacket::ConnAck {
            session_present: false,
            reason_code: 0x00,
        }
    );

    // Publish message to "factory/section3/temperature"
    let test_payload = Bytes::from_static(b"{\"temp\": 28.4, \"status\": \"OPTIMAL\"}");
    send_packet(
        &mut pub_stream,
        MqttPacket::Publish(PublishPacket {
            topic: "factory/section3/temperature".into(),
            qos: QoS::AtMostOnce,
            retain: false,
            dup: false,
            packet_id: None,
            payload: test_payload.clone(),
        }),
    )
    .await;

    // 4. Subscriber receives forwarded message over TCP
    let received_pkt = timeout(Duration::from_secs(2), read_packet(&mut sub_stream))
        .await
        .expect("Subscriber message reception timeout");

    if let MqttPacket::Publish(received_pub) = received_pkt {
        assert_eq!(received_pub.topic, "factory/section3/temperature");
        assert_eq!(received_pub.payload, test_payload);
    } else {
        panic!("Expected MqttPacket::Publish, got {:?}", received_pkt);
    }
}

#[tokio::test]
async fn test_e2e_ping_pong_and_clean_disconnect() {
    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();

    send_packet(
        &mut stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V311,
            client_id: "ping_client".into(),
            clean_start: true,
            keep_alive_sec: 10,
        }),
    )
    .await;

    let _ = timeout(Duration::from_secs(2), read_packet(&mut stream))
        .await
        .unwrap();

    // Send PINGREQ
    send_packet(&mut stream, MqttPacket::PingReq).await;
    let pingresp = timeout(Duration::from_secs(2), read_packet(&mut stream))
        .await
        .unwrap();
    assert_eq!(pingresp, MqttPacket::PingResp);

    // Send DISCONNECT
    send_packet(&mut stream, MqttPacket::Disconnect).await;
}

#[tokio::test]
async fn test_e2e_qos1_publish_and_puback() {
    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();

    send_packet(
        &mut stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "qos1_pub_client".into(),
            clean_start: true,
            keep_alive_sec: 60,
        }),
    )
    .await;

    let _ = timeout(Duration::from_secs(2), read_packet(&mut stream))
        .await
        .unwrap();

    // Send QoS 1 Publish with PacketID 777
    send_packet(
        &mut stream,
        MqttPacket::Publish(PublishPacket {
            topic: "critical/alarms".into(),
            qos: QoS::AtLeastOnce,
            retain: false,
            dup: false,
            packet_id: Some(777),
            payload: Bytes::from_static(b"CRITICAL_ALERT"),
        }),
    )
    .await;

    // Expect PubAck with matching packet_id 777
    let ack = timeout(Duration::from_secs(2), read_packet(&mut stream))
        .await
        .unwrap();
    assert_eq!(ack, MqttPacket::PubAck { packet_id: 777 });
}
