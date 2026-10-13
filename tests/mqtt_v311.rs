//! MQTT v3.1.1 behaviour over a live TCP listener.

mod common;

use bytes::Bytes;
use common::*;
use std::collections::HashSet;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use wolf_mqtt::auth::AclEngine;
use wolf_mqtt::broker::BrokerOptions;
use wolf_mqtt::client::RawClient;
use wolf_mqtt::protocol::{connack_v3, MqttPacket, ProtocolVersion, PublishPacket, QoS};

#[tokio::test]
async fn connect_ping_and_clean_disconnect() {
    let b = open_broker().await;
    let mut c = connect(b.addr, v3("pinger")).await;
    c.ping().await.unwrap();
    c.disconnect().await.unwrap();
}

#[tokio::test]
async fn fan_out_to_many_subscribers_with_qos_downgrade() {
    let b = open_broker().await;
    let mut subs = Vec::new();
    for i in 0..8 {
        let mut s = connect(b.addr, v3(&format!("sub-{i}"))).await;
        let qos = if i % 2 == 0 {
            QoS::AtMostOnce
        } else {
            QoS::ExactlyOnce
        };
        assert_eq!(s.subscribe("fleet/+/status", qos).await.unwrap(), qos as u8);
        subs.push((s, qos));
    }
    let mut publ = connect(b.addr, v3("publisher")).await;
    publ.publish(msg("fleet/7/status", b"ok", QoS::AtLeastOnce))
        .await
        .unwrap();
    for (s, granted) in subs.iter_mut() {
        let p = next_publish(s).await;
        assert_eq!(p.topic, "fleet/7/status");
        assert_eq!(&p.payload[..], b"ok");
        assert_eq!(p.qos, QoS::AtLeastOnce.min(*granted));
        assert!(!p.retain, "live delivery must clear RETAIN");
    }
}

#[tokio::test]
async fn qos2_publisher_flow_and_duplicate_suppression() {
    let b = open_broker().await;
    let mut sub = connect(b.addr, v3("q2-sub")).await;
    sub.subscribe("q2/topic", QoS::ExactlyOnce).await.unwrap();
    let mut publ = connect(b.addr, v3("q2-pub")).await;

    let mut m = msg("q2/topic", b"once", QoS::ExactlyOnce);
    m.packet_id = Some(7);
    publ.send(&MqttPacket::Publish(m.clone())).await.unwrap();
    assert_eq!(publ.recv().await.unwrap(), MqttPacket::pubrec(7));
    // Retransmission with DUP before PUBREL must not be delivered again.
    m.dup = true;
    publ.send(&MqttPacket::Publish(m)).await.unwrap();
    assert_eq!(publ.recv().await.unwrap(), MqttPacket::pubrec(7));
    publ.send(&MqttPacket::pubrel(7)).await.unwrap();
    assert_eq!(publ.recv().await.unwrap(), MqttPacket::pubcomp(7));

    let p = next_publish(&mut sub).await;
    assert_eq!(&p.payload[..], b"once");
    assert_no_publish(&mut sub).await;
}

#[tokio::test]
async fn outbound_packet_ids_are_unique_per_subscriber_across_publishers() {
    // Allow more unacknowledged deliveries than the default cap of 32.
    let mut options = BrokerOptions::permissive();
    options.max_inflight_messages = 100;
    let b = start_broker(options, AclEngine::new(true)).await;
    let mut sub = connect(b.addr, v3("pid-sub")).await;
    sub.subscribe("pid/#", QoS::AtLeastOnce).await.unwrap();

    let mut p1 = connect(b.addr, v3("pid-pub-1")).await;
    let mut p2 = connect(b.addr, v3("pid-pub-2")).await;
    for i in 0..20u8 {
        p1.publish(
            PublishPacket::new("pid/a", Bytes::from(vec![i])).with_qos(QoS::AtLeastOnce, None),
        )
        .await
        .unwrap();
        p2.publish(
            PublishPacket::new("pid/b", Bytes::from(vec![i])).with_qos(QoS::AtLeastOnce, None),
        )
        .await
        .unwrap();
    }
    // The subscriber does not acknowledge, so every identifier must still be distinct.
    let mut ids = HashSet::new();
    for _ in 0..40 {
        let p = sub
            .expect(|p| matches!(p, MqttPacket::Publish(_)))
            .await
            .unwrap();
        let MqttPacket::Publish(p) = p else {
            unreachable!()
        };
        let pid = p.packet_id.expect("QoS 1 has a packet id");
        assert_ne!(pid, 0);
        assert!(
            ids.insert(pid),
            "packet id {pid} reused while unacknowledged"
        );
    }
}

#[tokio::test]
async fn retained_messages_store_replace_clear_and_match_parent_level() {
    let b = open_broker().await;
    let mut publ = connect(b.addr, v3("ret-pub")).await;
    publ.publish(msg("sport", b"root", QoS::AtMostOnce).with_retain(true))
        .await
        .unwrap();
    publ.publish(msg("sport/tennis", b"v1", QoS::AtLeastOnce).with_retain(true))
        .await
        .unwrap();
    publ.publish(msg("sport/tennis", b"v2", QoS::AtLeastOnce).with_retain(true))
        .await
        .unwrap();

    let mut late = connect(b.addr, v3("ret-late")).await;
    late.subscribe("sport/#", QoS::AtLeastOnce).await.unwrap();
    let mut got = [next_publish(&mut late).await, next_publish(&mut late).await];
    got.sort_by(|a, b| a.topic.cmp(&b.topic));
    assert_eq!(got[0].topic, "sport");
    assert_eq!(&got[1].payload[..], b"v2");
    assert!(
        got.iter().all(|p| p.retain),
        "retained delivery must set RETAIN"
    );
    assert_eq!(got[0].qos, QoS::AtMostOnce);
    assert_eq!(got[1].qos, QoS::AtLeastOnce);

    // Zero-length retained payload clears the topic.
    publ.publish(msg("sport/tennis", b"", QoS::AtMostOnce).with_retain(true))
        .await
        .unwrap();
    let mut later = connect(b.addr, v3("ret-later")).await;
    later
        .subscribe("sport/tennis", QoS::AtMostOnce)
        .await
        .unwrap();
    assert_no_publish(&mut later).await;
}

#[tokio::test]
async fn will_is_published_on_abrupt_close_but_not_after_disconnect() {
    let b = open_broker().await;
    let mut watcher = connect(b.addr, v3("watcher")).await;
    watcher
        .subscribe("status/#", QoS::AtLeastOnce)
        .await
        .unwrap();

    let will = msg("status/dev1", b"offline", QoS::AtLeastOnce);
    let crashing = connect(b.addr, v3("dev1").with_will(will.clone())).await;
    drop(crashing.into_stream());
    let p = next_publish(&mut watcher).await;
    assert_eq!(p.topic, "status/dev1");
    assert_eq!(&p.payload[..], b"offline");

    let polite = connect(
        b.addr,
        v3("dev2").with_will(msg("status/dev2", b"offline", QoS::AtMostOnce)),
    )
    .await;
    polite.disconnect().await.unwrap();
    assert_no_publish(&mut watcher).await;
}

#[tokio::test]
async fn keep_alive_timeout_closes_connection_and_publishes_will() {
    let b = open_broker().await;
    let mut watcher = connect(b.addr, v3("ka-watcher")).await;
    watcher.subscribe("ka/will", QoS::AtMostOnce).await.unwrap();
    let mut idle = connect(
        b.addr,
        v3("ka-idle")
            .with_keep_alive(1)
            .with_will(msg("ka/will", b"gone", QoS::AtMostOnce)),
    )
    .await;
    // 1.5 x keep alive = 1.5 s.
    idle.wait_closed(Duration::from_secs(4)).await.unwrap();
    assert_eq!(&next_publish(&mut watcher).await.payload[..], b"gone");
}

#[tokio::test]
async fn unsubscribe_stops_delivery() {
    let b = open_broker().await;
    let mut sub = connect(b.addr, v3("unsub")).await;
    sub.subscribe("u/1", QoS::AtMostOnce).await.unwrap();
    assert!(sub
        .unsubscribe(&["u/1", "never/subscribed"])
        .await
        .unwrap()
        .is_empty());
    let mut publ = connect(b.addr, v3("unsub-pub")).await;
    publ.publish(msg("u/1", b"x", QoS::AtMostOnce))
        .await
        .unwrap();
    assert_no_publish(&mut sub).await;
}

#[tokio::test]
async fn invalid_filters_are_refused_in_suback() {
    let b = open_broker().await;
    let mut c = connect(b.addr, v3("bad-filters")).await;
    assert_eq!(c.subscribe("a/#/b", QoS::AtMostOnce).await.unwrap(), 0x80);
    assert_eq!(c.subscribe("a/b+", QoS::AtMostOnce).await.unwrap(), 0x80);
    assert_eq!(c.subscribe("a/+/b", QoS::AtMostOnce).await.unwrap(), 0x00);
}

#[tokio::test]
async fn protocol_violations_close_the_connection() {
    let b = open_broker().await;

    // A second CONNECT is a protocol violation.
    let mut c = connect(b.addr, v3("twice")).await;
    c.send(&MqttPacket::Connect(v3("twice"))).await.unwrap();
    c.wait_closed(Duration::from_secs(2)).await.unwrap();

    // The first packet must be CONNECT.
    let mut c = RawClient::new(
        wolf_mqtt::client::ClientStream::Tcp(TcpStream::connect(b.addr).await.unwrap()),
        ProtocolVersion::V311,
    );
    c.send(&MqttPacket::PingReq).await.unwrap();
    assert!(c
        .wait_closed(Duration::from_secs(2))
        .await
        .unwrap()
        .is_empty());

    // Garbage bytes.
    let mut raw = TcpStream::connect(b.addr).await.unwrap();
    raw.write_all(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00])
        .await
        .unwrap();
    let mut c = RawClient::new(
        wolf_mqtt::client::ClientStream::Tcp(raw),
        ProtocolVersion::V311,
    );
    c.wait_closed(Duration::from_secs(2)).await.unwrap();

    // The broker is still healthy.
    connect(b.addr, v3("still-alive"))
        .await
        .ping()
        .await
        .unwrap();
}

#[tokio::test]
async fn unsupported_protocol_level_gets_connack_0x01() {
    let b = open_broker().await;
    // MQTT v3.1 CONNECT ("MQIsdp", level 3).
    let raw = [
        0x10, 0x0F, 0x00, 0x06, b'M', b'Q', b'I', b's', b'd', b'p', 0x03, 0x02, 0x00, 0x3C, 0x00,
        0x01, b'a',
    ];
    let mut s = TcpStream::connect(b.addr).await.unwrap();
    s.write_all(&raw).await.unwrap();
    let mut c = RawClient::new(
        wolf_mqtt::client::ClientStream::Tcp(s),
        ProtocolVersion::V311,
    );
    let got = c.wait_closed(Duration::from_secs(2)).await.unwrap();
    assert_eq!(
        got,
        vec![MqttPacket::connack(
            false,
            connack_v3::UNACCEPTABLE_PROTOCOL_VERSION
        )]
    );
}

#[tokio::test]
async fn zero_length_client_id_rules() {
    let b = open_broker().await;
    let mut persistent = v3("");
    persistent.clean_start = false;
    let (_, ack) = RawClient::connect(b.addr, persistent).await.unwrap();
    assert_eq!(ack.reason_code, connack_v3::IDENTIFIER_REJECTED);

    let (mut c, ack) = RawClient::connect(b.addr, v3("")).await.unwrap();
    assert_eq!(ack.reason_code, 0);
    c.ping().await.unwrap();
}

#[tokio::test]
async fn connect_timeout_drops_silent_connections() {
    let mut options = BrokerOptions::permissive();
    options.connect_timeout = Duration::from_secs(1);
    let b = start_broker(options, AclEngine::new(true)).await;
    let s = TcpStream::connect(b.addr).await.unwrap();
    let mut c = RawClient::new(
        wolf_mqtt::client::ClientStream::Tcp(s),
        ProtocolVersion::V311,
    );
    let started = std::time::Instant::now();
    c.wait_closed(Duration::from_secs(3)).await.unwrap();
    assert!(started.elapsed() >= Duration::from_millis(900));
}

#[tokio::test]
async fn persistent_session_queues_messages_and_resends_unacknowledged() {
    let b = open_broker().await;
    let mut persistent = v3("persist");
    persistent.clean_start = false;

    let (mut c, ack) = RawClient::connect(b.addr, persistent.clone())
        .await
        .unwrap();
    assert!(!ack.session_present);
    c.subscribe("jobs/#", QoS::AtLeastOnce).await.unwrap();
    c.disconnect().await.unwrap();

    let mut publ = connect(b.addr, v3("persist-pub")).await;
    for i in 0..3u8 {
        publ.publish(
            PublishPacket::new("jobs/x", Bytes::from(vec![i])).with_qos(QoS::AtLeastOnce, None),
        )
        .await
        .unwrap();
    }

    // Resume: the queued messages arrive. Receive the first without acknowledging it.
    let (mut c, ack) = RawClient::connect(b.addr, persistent.clone())
        .await
        .unwrap();
    assert!(ack.session_present);
    let first = c
        .expect(|p| matches!(p, MqttPacket::Publish(_)))
        .await
        .unwrap();
    let MqttPacket::Publish(first) = first else {
        unreachable!()
    };
    assert_eq!(&first.payload[..], &[0]);
    drop(c.into_stream());
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Reconnect again: the unacknowledged message is resent with DUP=1 and its original id.
    let (mut c, ack) = RawClient::connect(b.addr, persistent).await.unwrap();
    assert!(ack.session_present);
    let again = next_publish(&mut c).await;
    assert!(again.dup);
    assert_eq!(again.packet_id, first.packet_id);
    assert_eq!(&next_publish(&mut c).await.payload[..], &[1]);
    assert_eq!(&next_publish(&mut c).await.payload[..], &[2]);

    // A clean session discards everything.
    c.disconnect().await.unwrap();
    let (_, ack) = RawClient::connect(b.addr, v3("persist")).await.unwrap();
    assert!(!ack.session_present);
}

#[tokio::test]
async fn reconnect_with_same_client_id_closes_previous_connection() {
    let b = open_broker().await;
    let mut watcher = connect(b.addr, v3("tk-watch")).await;
    watcher.subscribe("tk/will", QoS::AtMostOnce).await.unwrap();
    let mut old = connect(
        b.addr,
        v3("dup-id").with_will(msg("tk/will", b"replaced", QoS::AtMostOnce)),
    )
    .await;
    let mut new = connect(b.addr, v3("dup-id")).await;
    old.wait_closed(Duration::from_secs(2)).await.unwrap();
    assert_eq!(&next_publish(&mut watcher).await.payload[..], b"replaced");
    new.ping().await.unwrap();
}

#[tokio::test]
async fn takeover_never_resumes_a_non_persistent_session() {
    let b = open_broker().await;
    // A clean session (expiry 0) with a subscription, still connected.
    let mut a = connect(b.addr, v3("shared-cid")).await;
    a.subscribe("np/#", QoS::AtMostOnce).await.unwrap();
    // A takeover asking to resume must not inherit it (MQTT-3.1.2-6).
    let mut resume = v3("shared-cid");
    resume.clean_start = false;
    let (mut c, ack) = RawClient::connect(b.addr, resume).await.unwrap();
    assert!(!ack.session_present);
    a.wait_closed(Duration::from_secs(2)).await.unwrap();
    let mut publ = connect(b.addr, v3("np-pub")).await;
    publ.publish(msg("np/1", b"x", QoS::AtMostOnce))
        .await
        .unwrap();
    assert_no_publish(&mut c).await;
}
