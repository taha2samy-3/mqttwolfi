//! Resource limits: session queue overflow policies, connection limit, packet size limit.

mod common;

use bytes::Bytes;
use common::*;
use std::time::Duration;
use tokio::net::TcpStream;
use wolf_mqtt::auth::AclEngine;
use wolf_mqtt::broker::BrokerOptions;
use wolf_mqtt::client::{ClientStream, RawClient};
use wolf_mqtt::config::QueueFullPolicy;
use wolf_mqtt::protocol::{MqttPacket, Properties, Property, ProtocolVersion, PublishPacket, QoS};

/// Queues 10 messages for an offline session limited to 5 and returns what it receives.
async fn overflow_offline_queue(policy: QueueFullPolicy) -> Vec<u8> {
    let mut options = BrokerOptions::permissive();
    options.queue_limits.max_messages = 5;
    options.queue_limits.policy = policy;
    let b = start_broker(options, AclEngine::new(true)).await;

    let mut conn = v5("slow");
    conn.properties = Properties(vec![Property::SessionExpiryInterval(60)]);
    let mut c = connect(b.addr, conn.clone()).await;
    c.subscribe("q/#", QoS::AtLeastOnce).await.unwrap();
    c.disconnect().await.unwrap();

    let mut publ = connect(b.addr, v5("fast")).await;
    for i in 1..=10u8 {
        publ.publish(
            PublishPacket::new("q/x", Bytes::from(vec![i])).with_qos(QoS::AtLeastOnce, None),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        b.ctx
            .metrics
            .messages_dropped
            .load(std::sync::atomic::Ordering::Relaxed),
        5
    );

    conn.clean_start = false;
    let mut c = connect(b.addr, conn).await;
    let mut got = Vec::new();
    while let Ok(Some(MqttPacket::Publish(p))) = c.recv_timeout(QUIET).await {
        c.ack_publish(&p).await.unwrap();
        got.push(p.payload[0]);
    }
    got
}

#[tokio::test]
async fn drop_oldest_keeps_the_newest_messages() {
    assert_eq!(
        overflow_offline_queue(QueueFullPolicy::DropOldest).await,
        vec![6, 7, 8, 9, 10]
    );
}

#[tokio::test]
async fn drop_newest_keeps_the_oldest_messages() {
    assert_eq!(
        overflow_offline_queue(QueueFullPolicy::DropNewest).await,
        vec![1, 2, 3, 4, 5]
    );
}

#[tokio::test]
async fn connection_limit_is_enforced() {
    let mut options = BrokerOptions::permissive();
    options.max_connections = 2;
    let b = start_broker(options, AclEngine::new(true)).await;
    let _a = connect(b.addr, v3("c1")).await;
    let _b = connect(b.addr, v3("c2")).await;
    let s = TcpStream::connect(b.addr).await.unwrap();
    let mut third = RawClient::new(ClientStream::Tcp(s), ProtocolVersion::V311);
    let _ = third.send(&MqttPacket::Connect(v3("c3"))).await;
    assert!(third
        .wait_closed(Duration::from_secs(2))
        .await
        .unwrap()
        .is_empty());

    // Closing a connection frees its slot.
    drop(_a);
    tokio::time::sleep(Duration::from_millis(200)).await;
    connect(b.addr, v3("c4")).await.ping().await.unwrap();
}

#[tokio::test]
async fn oversized_packets_close_v311_connections() {
    let mut options = BrokerOptions::permissive();
    options.max_packet_size = 512;
    let b = start_broker(options, AclEngine::new(true)).await;
    let mut c = connect(b.addr, v3("big")).await;
    c.send(&MqttPacket::Publish(PublishPacket::new(
        "t",
        Bytes::from(vec![0u8; 2048]),
    )))
    .await
    .unwrap();
    assert!(c
        .wait_closed(Duration::from_secs(2))
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn unacknowledged_deliveries_are_capped_by_the_broker() {
    // v3.1.1 clients announce no Receive Maximum; the broker's own inflight cap applies.
    let mut options = BrokerOptions::permissive();
    options.max_inflight_messages = 3;
    let b = start_broker(options, AclEngine::new(true)).await;
    let mut sub = connect(b.addr, v3("lazy-acker")).await;
    sub.subscribe("cap/#", QoS::AtLeastOnce).await.unwrap();
    let mut publ = connect(b.addr, v3("cap-pub")).await;
    for i in 0..10u8 {
        publ.publish(
            PublishPacket::new("cap/x", Bytes::from(vec![i])).with_qos(QoS::AtLeastOnce, None),
        )
        .await
        .unwrap();
    }
    let mut held = Vec::new();
    while let Ok(Some(MqttPacket::Publish(p))) = sub.recv_timeout(QUIET).await {
        held.push(p);
    }
    assert_eq!(
        held.len(),
        3,
        "only max_inflight_messages may be unacknowledged"
    );
    sub.ack_publish(&held[0]).await.unwrap();
    let next = sub
        .expect(|p| matches!(p, MqttPacket::Publish(_)))
        .await
        .unwrap();
    let MqttPacket::Publish(next) = next else {
        unreachable!()
    };
    assert_eq!(&next.payload[..], &[3]);
}
