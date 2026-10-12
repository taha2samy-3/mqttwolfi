use bytes::{Buf, Bytes, BytesMut};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use wolf_mqtt::protocol::{ConnectPacket, MqttPacket, ProtocolVersion, PublishPacket, QoS};
use wolf_mqtt::server::BrokerServer;

async fn send_packet(stream: &mut TcpStream, packet: MqttPacket) {
    let mut buf = BytesMut::new();
    packet.encode(&mut buf).expect("Failed to encode packet");
    stream.write_all(&buf).await.expect("Failed to write to stream");
}

async fn read_packet(stream: &mut TcpStream, buf: &mut BytesMut) -> MqttPacket {
    loop {
        if !buf.is_empty() {
            let mut slice = &buf[..];
            if let Ok(pkt) = MqttPacket::decode(&mut slice) {
                let consumed = buf.len() - slice.len();
                buf.advance(consumed);
                return pkt;
            }
        }
        let n = stream.read_buf(buf).await.expect("Socket read failed");
        assert!(n > 0, "Unexpected EOF while reading packet");
    }
}

#[tokio::test]
async fn test_live_tcp_high_concurrency_fanout_1_to_8() {
    let server = BrokerServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    let num_subscribers = 8;
    let num_messages = 10;
    let mut sub_handles = Vec::new();

    // Spawn 8 concurrent subscriber tasks connecting via real TCP sockets
    for client_idx in 0..num_subscribers {
        let handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let mut read_buf = BytesMut::with_capacity(4096);

            send_packet(
                &mut stream,
                MqttPacket::Connect(ConnectPacket {
                    version: ProtocolVersion::V500,
                    client_id: format!("sub_client_{}", client_idx),
                    clean_start: true,
                    keep_alive_sec: 60,
                    will: None,
                }),
            )
            .await;

            let _ = timeout(Duration::from_secs(3), read_packet(&mut stream, &mut read_buf))
                .await
                .expect("ConnAck timeout");

            send_packet(
                &mut stream,
                MqttPacket::Subscribe {
                    packet_id: 1,
                    topics: vec![("broadcast/metrics".into(), QoS::AtMostOnce)],
                },
            )
            .await;

            let _ = timeout(Duration::from_secs(3), read_packet(&mut stream, &mut read_buf))
                .await
                .expect("SubAck timeout");

            // Receive all expected messages
            let mut received_count = 0;
            for _ in 0..num_messages {
                let pkt = timeout(Duration::from_secs(3), read_packet(&mut stream, &mut read_buf))
                    .await
                    .expect("Message recv timeout");
                if let MqttPacket::Publish(pub_pkt) = pkt {
                    assert_eq!(pub_pkt.topic, "broadcast/metrics");
                    received_count += 1;
                }
            }
            received_count
        });
        sub_handles.push(handle);
    }

    // Give subscribers time to establish connections and subscriptions
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Connect publisher and send messages
    let mut pub_stream = TcpStream::connect(addr).await.unwrap();
    let mut pub_buf = BytesMut::with_capacity(1024);
    send_packet(
        &mut pub_stream,
        MqttPacket::Connect(ConnectPacket {
            version: ProtocolVersion::V500,
            client_id: "broadcaster_pub".into(),
            clean_start: true,
            keep_alive_sec: 60,
            will: None,
        }),
    )
    .await;
    let _ = timeout(Duration::from_secs(3), read_packet(&mut pub_stream, &mut pub_buf))
        .await
        .unwrap();

    for i in 0..num_messages {
        let payload = format!("payload_seq_{}", i);
        send_packet(
            &mut pub_stream,
            MqttPacket::Publish(PublishPacket {
                topic: "broadcast/metrics".into(),
                qos: QoS::AtMostOnce,
                retain: false,
                dup: false,
                packet_id: None,
                payload: Bytes::from(payload),
            }),
        )
        .await;
    }

    // Collect results from all subscribers
    for handle in sub_handles {
        let count = handle.await.unwrap();
        assert_eq!(count, num_messages, "Each subscriber must receive all published messages");
    }
}
