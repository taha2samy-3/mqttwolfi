//! MQTT-SN v1.2 gateway over UDP, including cross-protocol delivery with MQTT clients.

mod common;

use bytes::{Bytes, BytesMut};
use common::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use wolf_mqtt::auth::AclEngine;
use wolf_mqtt::broker::BrokerOptions;
use wolf_mqtt::config::MqttSnListenerConfig;
use wolf_mqtt::protocol::sn::{return_code, SnPacket, TopicIdType};
use wolf_mqtt::protocol::QoS;
use wolf_mqtt::server_sn::MqttSnServer;

struct SnTest {
    broker: TestBroker,
    gw: SocketAddr,
}

async fn sn_setup(acl: AclEngine, tweak: impl FnOnce(&mut MqttSnListenerConfig)) -> SnTest {
    let broker = start_broker(BrokerOptions::permissive(), acl).await;
    let mut predefined = HashMap::new();
    predefined.insert("1".to_string(), "uav/drone_01/telemetry/gps".to_string());
    predefined.insert("2".to_string(), "uav/drone_01/commands".to_string());
    let mut cfg = MqttSnListenerConfig {
        enabled: true,
        bind_address: "127.0.0.1".into(),
        port: 0,
        advertise_interval_sec: 0,
        predefined_topics: predefined,
        ..Default::default()
    };
    tweak(&mut cfg);
    let sn = MqttSnServer::bind(cfg, broker.ctx.clone()).await.unwrap();
    let gw = sn.local_addr().unwrap();
    tokio::spawn(sn.run());
    SnTest { broker, gw }
}

struct SnClient {
    sock: UdpSocket,
    gw: SocketAddr,
}

impl SnClient {
    async fn new(gw: SocketAddr) -> Self {
        Self {
            sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            gw,
        }
    }

    async fn send(&self, p: &SnPacket) {
        let buf = p.to_bytes().unwrap();
        self.sock.send_to(&buf, self.gw).await.unwrap();
    }

    async fn recv(&self) -> SnPacket {
        self.recv_timeout(Duration::from_secs(3))
            .await
            .expect("expected an MQTT-SN packet")
    }

    async fn recv_timeout(&self, d: Duration) -> Option<SnPacket> {
        let mut buf = vec![0u8; 65_535];
        let (n, _) = tokio::time::timeout(d, self.sock.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        let mut slice = &buf[..n];
        Some(SnPacket::decode(&mut slice).expect("valid MQTT-SN frame"))
    }

    async fn connect(&self, client_id: &str, duration: u16) {
        self.send(&SnPacket::Connect {
            will: false,
            clean_session: true,
            duration,
            client_id: client_id.into(),
        })
        .await;
        assert_eq!(self.recv().await, SnPacket::ConnAck { return_code: 0 });
    }

    async fn subscribe_name(&self, filter: &str, qos: u8, msg_id: u16) -> SnPacket {
        self.send(&SnPacket::Subscribe {
            dup: false,
            qos,
            topic_id_type: TopicIdType::Normal,
            msg_id,
            topic_id: 0,
            topic_name: Some(filter.into()),
        })
        .await;
        self.recv().await
    }
}

fn sn_publish(
    qos: i8,
    id_type: TopicIdType,
    topic_id: u16,
    msg_id: u16,
    data: &'static [u8],
) -> SnPacket {
    SnPacket::Publish {
        dup: false,
        qos,
        retain: false,
        topic_id_type: id_type,
        topic_id,
        msg_id,
        data: Bytes::from_static(data),
    }
}

#[tokio::test]
async fn connect_ping_disconnect() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let c = SnClient::new(t.gw).await;
    c.connect("drone-1", 30).await;
    c.send(&SnPacket::PingReq { client_id: None }).await;
    assert_eq!(c.recv().await, SnPacket::PingResp);
    c.send(&SnPacket::Disconnect { duration: None }).await;
    assert_eq!(c.recv().await, SnPacket::Disconnect { duration: None });
}

#[tokio::test]
async fn register_and_publish_reach_mqtt_subscribers() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let mut gcs = connect(t.broker.addr, v5("ground-station")).await;
    gcs.subscribe("uav/#", QoS::AtLeastOnce).await.unwrap();

    let c = SnClient::new(t.gw).await;
    c.connect("drone-2", 60).await;
    c.send(&SnPacket::Register {
        topic_id: 0,
        msg_id: 1,
        topic_name: "uav/drone_02/temp".into(),
    })
    .await;
    let SnPacket::RegAck {
        topic_id,
        msg_id: 1,
        return_code: 0,
    } = c.recv().await
    else {
        panic!("expected REGACK")
    };
    c.send(&sn_publish(1, TopicIdType::Normal, topic_id, 2, b"25.4C"))
        .await;
    assert_eq!(
        c.recv().await,
        SnPacket::PubAck {
            topic_id,
            msg_id: 2,
            return_code: 0
        }
    );
    let p = next_publish(&mut gcs).await;
    assert_eq!(p.topic, "uav/drone_02/temp");
    assert_eq!(&p.payload[..], b"25.4C");

    // Unknown topic ids are rejected.
    c.send(&sn_publish(1, TopicIdType::Normal, 999, 3, b"x"))
        .await;
    assert_eq!(
        c.recv().await,
        SnPacket::PubAck {
            topic_id: 999,
            msg_id: 3,
            return_code: return_code::REJECTED_INVALID_TOPIC_ID
        }
    );
}

#[tokio::test]
async fn qos_minus1_publish_without_connection() {
    let t = sn_setup(AclEngine::new(true), |cfg| cfg.allow_qos_minus1 = true).await;
    let mut gcs = connect(t.broker.addr, v3("gcs-m1")).await;
    gcs.subscribe("uav/drone_01/telemetry/gps", QoS::AtMostOnce)
        .await
        .unwrap();
    let c = SnClient::new(t.gw).await;
    c.send(&sn_publish(-1, TopicIdType::Predefined, 1, 0, b"lat=30.04"))
        .await;
    assert_eq!(&next_publish(&mut gcs).await.payload[..], b"lat=30.04");
}

#[tokio::test]
async fn mqtt_to_sn_delivery_preserves_binary_payloads() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let c = SnClient::new(t.gw).await;
    c.connect("drone-3", 60).await;
    c.send(&SnPacket::Subscribe {
        dup: false,
        qos: 1,
        topic_id_type: TopicIdType::Predefined,
        msg_id: 10,
        topic_id: 2,
        topic_name: None,
    })
    .await;
    assert_eq!(
        c.recv().await,
        SnPacket::SubAck {
            qos: 1,
            topic_id: 2,
            msg_id: 10,
            return_code: 0
        }
    );

    let mut gcs = connect(t.broker.addr, v5("gcs-cmd")).await;
    let binary: &'static [u8] = &[0x00, 0x01, 0xFF, 0x00];
    gcs.publish(msg("uav/drone_01/commands", binary, QoS::AtLeastOnce))
        .await
        .unwrap();
    match c.recv().await {
        SnPacket::Publish {
            qos: 1,
            topic_id_type: TopicIdType::Predefined,
            topic_id: 2,
            msg_id,
            data,
            ..
        } => {
            assert_eq!(&data[..], binary);
            c.send(&SnPacket::PubAck {
                topic_id: 2,
                msg_id,
                return_code: 0,
            })
            .await;
        }
        other => panic!("expected PUBLISH, got {other:?}"),
    }
}

#[tokio::test]
async fn wildcard_subscription_registers_topics_before_publishing() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let c = SnClient::new(t.gw).await;
    c.connect("drone-4", 60).await;
    let SnPacket::SubAck {
        topic_id: 0,
        return_code: 0,
        ..
    } = c.subscribe_name("fleet/+/cmd", 0, 1).await
    else {
        panic!("wildcard SUBACK must carry topic id 0")
    };

    let mut publ = connect(t.broker.addr, v3("fleet-ctl")).await;
    publ.publish(msg("fleet/7/cmd", b"land", QoS::AtMostOnce))
        .await
        .unwrap();

    let SnPacket::Register {
        topic_id,
        msg_id,
        topic_name,
    } = c.recv().await
    else {
        panic!("expected REGISTER")
    };
    assert_eq!(topic_name, "fleet/7/cmd");
    // The PUBLISH is held back until the client acknowledges the registration.
    assert!(c.recv_timeout(QUIET).await.is_none());
    c.send(&SnPacket::RegAck {
        topic_id,
        msg_id,
        return_code: 0,
    })
    .await;
    match c.recv().await {
        SnPacket::Publish {
            topic_id: t2,
            topic_id_type: TopicIdType::Normal,
            data,
            ..
        } => {
            assert_eq!(t2, topic_id);
            assert_eq!(&data[..], b"land");
        }
        other => panic!("expected PUBLISH, got {other:?}"),
    }
}

#[tokio::test]
async fn will_handshake_and_will_on_timeout() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let mut watcher = connect(t.broker.addr, v5("sn-watch")).await;
    watcher
        .subscribe("uav/+/lwt", QoS::AtMostOnce)
        .await
        .unwrap();

    let c = SnClient::new(t.gw).await;
    c.send(&SnPacket::Connect {
        will: true,
        clean_session: true,
        duration: 1,
        client_id: "drone-5".into(),
    })
    .await;
    assert_eq!(c.recv().await, SnPacket::WillTopicReq);
    c.send(&SnPacket::WillTopic {
        qos: 0,
        retain: false,
        will_topic: "uav/drone_05/lwt".into(),
    })
    .await;
    assert_eq!(c.recv().await, SnPacket::WillMsgReq);
    c.send(&SnPacket::WillMsg {
        will_msg: Bytes::from_static(b"LINK_LOST"),
    })
    .await;
    assert_eq!(c.recv().await, SnPacket::ConnAck { return_code: 0 });

    // No traffic for 1.5 x keep alive: the gateway declares the client lost.
    let p = tokio::time::timeout(Duration::from_secs(4), watcher.recv_publish())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p.topic, "uav/drone_05/lwt");
    assert_eq!(&p.payload[..], b"LINK_LOST");
}

#[tokio::test]
async fn qos2_inbound_flow_suppresses_duplicates() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let mut gcs = connect(t.broker.addr, v3("gcs-q2")).await;
    gcs.subscribe("uav/drone_01/telemetry/gps", QoS::ExactlyOnce)
        .await
        .unwrap();
    let c = SnClient::new(t.gw).await;
    c.connect("drone-6", 60).await;

    let p = sn_publish(2, TopicIdType::Predefined, 1, 77, b"fix");
    c.send(&p).await;
    assert_eq!(c.recv().await, SnPacket::PubRec { msg_id: 77 });
    c.send(&p).await;
    assert_eq!(c.recv().await, SnPacket::PubRec { msg_id: 77 });
    c.send(&SnPacket::PubRel { msg_id: 77 }).await;
    assert_eq!(c.recv().await, SnPacket::PubComp { msg_id: 77 });

    assert_eq!(&next_publish(&mut gcs).await.payload[..], b"fix");
    assert_no_publish(&mut gcs).await;
}

#[tokio::test]
async fn unacknowledged_qos1_messages_are_retransmitted_with_dup() {
    let t = sn_setup(AclEngine::new(true), |cfg| cfg.retry_interval_sec = 1).await;
    let c = SnClient::new(t.gw).await;
    c.connect("drone-7", 60).await;
    c.send(&SnPacket::Subscribe {
        dup: false,
        qos: 1,
        topic_id_type: TopicIdType::Predefined,
        msg_id: 1,
        topic_id: 2,
        topic_name: None,
    })
    .await;
    c.recv().await;

    let mut gcs = connect(t.broker.addr, v3("gcs-rt")).await;
    gcs.publish(msg("uav/drone_01/commands", b"rtl", QoS::AtLeastOnce))
        .await
        .unwrap();
    let SnPacket::Publish {
        dup: false, msg_id, ..
    } = c.recv().await
    else {
        panic!("expected first PUBLISH")
    };
    let SnPacket::Publish {
        dup: true,
        msg_id: again,
        ..
    } = c.recv().await
    else {
        panic!("expected retransmitted PUBLISH")
    };
    assert_eq!(msg_id, again);
}

#[tokio::test]
async fn sleeping_clients_receive_buffered_messages_on_wake_up() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let c = SnClient::new(t.gw).await;
    c.connect("drone-8", 60).await;
    c.send(&SnPacket::Subscribe {
        dup: false,
        qos: 0,
        topic_id_type: TopicIdType::Predefined,
        msg_id: 1,
        topic_id: 2,
        topic_name: None,
    })
    .await;
    c.recv().await;
    c.send(&SnPacket::Disconnect { duration: Some(30) }).await;
    assert_eq!(c.recv().await, SnPacket::Disconnect { duration: None });

    let mut gcs = connect(t.broker.addr, v3("gcs-sleep")).await;
    for payload in [b"cmd-1", b"cmd-2"] {
        gcs.publish(msg("uav/drone_01/commands", payload, QoS::AtMostOnce))
            .await
            .unwrap();
    }
    assert!(
        c.recv_timeout(QUIET).await.is_none(),
        "nothing is sent while asleep"
    );

    c.send(&SnPacket::PingReq {
        client_id: Some("drone-8".into()),
    })
    .await;
    let mut got = Vec::new();
    for _ in 0..2 {
        match c.recv().await {
            SnPacket::Publish { data, .. } => got.push(data),
            other => panic!("expected buffered PUBLISH, got {other:?}"),
        }
    }
    assert_eq!(
        got,
        vec![Bytes::from_static(b"cmd-1"), Bytes::from_static(b"cmd-2")]
    );
    assert_eq!(c.recv().await, SnPacket::PingResp);
}

#[tokio::test]
async fn configured_acl_identity_is_enforced() {
    let acl = AclEngine::new(false);
    acl.load_from_acl_file("config/acl.conf").await.unwrap();
    let t = sn_setup(acl, |cfg| cfg.acl_user = "sn_gateway".into()).await;
    let c = SnClient::new(t.gw).await;
    c.connect("drone-9", 60).await;

    // sn_gateway may publish under uav/# ...
    c.send(&sn_publish(1, TopicIdType::Predefined, 1, 1, b"ok"))
        .await;
    assert!(matches!(
        c.recv().await,
        SnPacket::PubAck { return_code: 0, .. }
    ));
    // ... but not elsewhere.
    c.send(&SnPacket::Register {
        topic_id: 0,
        msg_id: 2,
        topic_name: "rooms/engineering/chat".into(),
    })
    .await;
    let SnPacket::RegAck { topic_id, .. } = c.recv().await else {
        panic!()
    };
    c.send(&sn_publish(1, TopicIdType::Normal, topic_id, 3, b"no"))
        .await;
    assert!(matches!(
        c.recv().await,
        SnPacket::PubAck {
            return_code: return_code::REJECTED_NOT_SUPPORTED,
            ..
        }
    ));
    // Will topics are authorized too.
    let w = SnClient::new(t.gw).await;
    w.send(&SnPacket::Connect {
        will: true,
        clean_session: true,
        duration: 60,
        client_id: "drone-10".into(),
    })
    .await;
    w.recv().await;
    w.send(&SnPacket::WillTopic {
        qos: 0,
        retain: false,
        will_topic: "rooms/engineering/chat".into(),
    })
    .await;
    w.recv().await;
    w.send(&SnPacket::WillMsg {
        will_msg: Bytes::from_static(b"x"),
    })
    .await;
    assert_eq!(
        w.recv().await,
        SnPacket::ConnAck {
            return_code: return_code::REJECTED_NOT_SUPPORTED
        }
    );
}

#[tokio::test]
async fn connections_are_rejected_without_an_identity() {
    let t = sn_setup(AclEngine::new(false), |_| {}).await;
    let c = SnClient::new(t.gw).await;
    c.send(&SnPacket::Connect {
        will: false,
        clean_session: true,
        duration: 60,
        client_id: "nobody".into(),
    })
    .await;
    assert_eq!(
        c.recv().await,
        SnPacket::ConnAck {
            return_code: return_code::REJECTED_NOT_SUPPORTED
        }
    );
    // QoS -1 is not a way around authorization.
    let mut gcs = connect_admin_less(&t).await;
    c.send(&sn_publish(-1, TopicIdType::Predefined, 1, 0, b"sneaky"))
        .await;
    assert_no_publish(&mut gcs).await;
}

async fn connect_admin_less(t: &SnTest) -> wolf_mqtt::client::RawClient {
    // The broker rejects anonymous MQTT clients too, so watch through an admin account.
    t.broker
        .ctx
        .acl
        .add_user(wolf_mqtt::auth::UserAccount::new_admin("watch", "pw"))
        .await;
    let mut c = connect(t.broker.addr, v5("watcher").with_credentials("watch", "pw")).await;
    c.subscribe("uav/#", QoS::AtMostOnce).await.unwrap();
    c
}

#[tokio::test]
async fn encapsulated_frames_are_answered_encapsulated() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let c = SnClient::new(t.gw).await;
    let inner = SnPacket::Connect {
        will: false,
        clean_session: true,
        duration: 60,
        client_id: "behind-forwarder".into(),
    }
    .to_bytes()
    .unwrap()
    .freeze();
    c.send(&SnPacket::EncapMsg {
        ctrl: 0,
        wireless_node_id: vec![0xAB, 0xCD],
        payload: inner,
    })
    .await;
    match c.recv().await {
        SnPacket::EncapMsg {
            wireless_node_id,
            payload,
            ..
        } => {
            assert_eq!(wireless_node_id, vec![0xAB, 0xCD]);
            let mut s = &payload[..];
            assert_eq!(
                SnPacket::decode(&mut s).unwrap(),
                SnPacket::ConnAck { return_code: 0 }
            );
        }
        other => panic!("expected encapsulated CONNACK, got {other:?}"),
    }
}

#[tokio::test]
async fn retained_messages_are_delivered_to_sn_subscribers() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let mut publ = connect(t.broker.addr, v3("ret-pub")).await;
    publ.publish(msg("uav/drone_01/commands", b"hold", QoS::AtMostOnce).with_retain(true))
        .await
        .unwrap();
    let c = SnClient::new(t.gw).await;
    c.connect("drone-11", 60).await;
    c.send(&SnPacket::Subscribe {
        dup: false,
        qos: 0,
        topic_id_type: TopicIdType::Predefined,
        msg_id: 1,
        topic_id: 2,
        topic_name: None,
    })
    .await;
    assert!(matches!(c.recv().await, SnPacket::SubAck { .. }));
    match c.recv().await {
        SnPacket::Publish { retain, data, .. } => {
            assert!(retain);
            assert_eq!(&data[..], b"hold");
        }
        other => panic!("expected retained PUBLISH, got {other:?}"),
    }
}

#[tokio::test]
async fn session_limit_is_enforced() {
    let t = sn_setup(AclEngine::new(true), |cfg| cfg.max_sessions = 1).await;
    let a = SnClient::new(t.gw).await;
    a.connect("only-one", 60).await;
    let b = SnClient::new(t.gw).await;
    b.send(&SnPacket::Connect {
        will: false,
        clean_session: true,
        duration: 60,
        client_id: "too-many".into(),
    })
    .await;
    assert_eq!(
        b.recv().await,
        SnPacket::ConnAck {
            return_code: return_code::REJECTED_CONGESTION
        }
    );
    let _ = BytesMut::new();
}

#[tokio::test]
async fn short_topic_ids_with_nul_are_rejected() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let mut all = connect(t.broker.addr, v3("nul-watch")).await;
    all.subscribe("#", QoS::AtMostOnce).await.unwrap();
    let c = SnClient::new(t.gw).await;
    c.connect("drone-nul", 60).await;
    c.send(&sn_publish(1, TopicIdType::Short, 0x0041, 5, b"x"))
        .await;
    assert_eq!(
        c.recv().await,
        SnPacket::PubAck {
            topic_id: 0x0041,
            msg_id: 5,
            return_code: return_code::REJECTED_INVALID_TOPIC_ID
        }
    );
    c.send(&sn_publish(-1, TopicIdType::Short, 0x0041, 0, b"y"))
        .await;
    assert_no_publish(&mut all).await;
    // The MQTT subscriber is still connected and healthy.
    all.ping().await.unwrap();
}

#[tokio::test]
async fn clients_with_keep_alive_zero_are_reaped_when_idle() {
    let t = sn_setup(AclEngine::new(true), |cfg| cfg.max_idle_sec = 1).await;
    let c = SnClient::new(t.gw).await;
    c.connect("idle-forever", 0).await;
    assert_eq!(t.broker.ctx.session_count(), 1);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(t.broker.ctx.session_count(), 0);
}

#[tokio::test]
async fn unacknowledged_messages_survive_an_sn_reconnect() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let c = SnClient::new(t.gw).await;
    let connect = |clean_session| SnPacket::Connect {
        will: false,
        clean_session,
        duration: 60,
        client_id: "persistent-drone".into(),
    };
    c.send(&connect(false)).await;
    assert_eq!(c.recv().await, SnPacket::ConnAck { return_code: 0 });
    c.send(&SnPacket::Subscribe {
        dup: false,
        qos: 1,
        topic_id_type: TopicIdType::Predefined,
        msg_id: 1,
        topic_id: 2,
        topic_name: None,
    })
    .await;
    c.recv().await;

    let mut gcs = connect_v3_helper(&t).await;
    gcs.publish(msg("uav/drone_01/commands", b"keep-me", QoS::AtLeastOnce))
        .await
        .unwrap();
    let SnPacket::Publish { data, .. } = c.recv().await else {
        panic!("expected PUBLISH")
    };
    assert_eq!(&data[..], b"keep-me");

    // Reconnect without acknowledging: CONNACK first (§6.2), then the message again with DUP.
    c.send(&connect(false)).await;
    assert_eq!(c.recv().await, SnPacket::ConnAck { return_code: 0 });
    let SnPacket::Publish {
        dup: true, data, ..
    } = c.recv().await
    else {
        panic!("expected the unacknowledged PUBLISH again")
    };
    assert_eq!(&data[..], b"keep-me");
}

async fn connect_v3_helper(t: &SnTest) -> wolf_mqtt::client::RawClient {
    connect(t.broker.addr, v3("gcs-persist")).await
}

fn connect_packet(client_id: &str, clean_session: bool) -> SnPacket {
    SnPacket::Connect {
        will: false,
        clean_session,
        duration: 60,
        client_id: client_id.into(),
    }
}

#[tokio::test]
async fn registered_topics_survive_a_persistent_reconnect() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let mut gcs = connect(t.broker.addr, v3("gcs-reg")).await;
    gcs.subscribe("fleet/#", QoS::AtLeastOnce).await.unwrap();

    let c = SnClient::new(t.gw).await;
    c.send(&connect_packet("reg-keeper", false)).await;
    assert_eq!(c.recv().await, SnPacket::ConnAck { return_code: 0 });
    c.send(&SnPacket::Register {
        topic_id: 0,
        msg_id: 1,
        topic_name: "fleet/alpha".into(),
    })
    .await;
    let SnPacket::RegAck {
        topic_id,
        return_code: 0,
        ..
    } = c.recv().await
    else {
        panic!("expected REGACK")
    };
    c.send(&SnPacket::Disconnect { duration: None }).await;
    c.recv().await;

    // Same client from a new address (e.g. after a NAT rebinding), without clean session.
    let c2 = SnClient::new(t.gw).await;
    c2.send(&connect_packet("reg-keeper", false)).await;
    assert_eq!(c2.recv().await, SnPacket::ConnAck { return_code: 0 });
    c2.send(&sn_publish(
        1,
        TopicIdType::Normal,
        topic_id,
        2,
        b"still-known",
    ))
    .await;
    assert_eq!(
        c2.recv().await,
        SnPacket::PubAck {
            topic_id,
            msg_id: 2,
            return_code: 0
        }
    );
    let p = next_publish(&mut gcs).await;
    assert_eq!(p.topic, "fleet/alpha");

    // A clean session forgets the registrations.
    c2.send(&connect_packet("reg-keeper", true)).await;
    assert_eq!(c2.recv().await, SnPacket::ConnAck { return_code: 0 });
    c2.send(&sn_publish(1, TopicIdType::Normal, topic_id, 3, b"gone"))
        .await;
    assert_eq!(
        c2.recv().await,
        SnPacket::PubAck {
            topic_id,
            msg_id: 3,
            return_code: return_code::REJECTED_INVALID_TOPIC_ID
        }
    );
}

#[tokio::test]
async fn offline_persistent_sessions_count_against_the_session_limit() {
    let t = sn_setup(AclEngine::new(true), |cfg| cfg.max_sessions = 1).await;
    let a = SnClient::new(t.gw).await;
    a.send(&connect_packet("persisted", false)).await;
    assert_eq!(a.recv().await, SnPacket::ConnAck { return_code: 0 });
    a.send(&SnPacket::Disconnect { duration: None }).await;
    a.recv().await;

    let b = SnClient::new(t.gw).await;
    b.send(&connect_packet("newcomer", true)).await;
    assert_eq!(
        b.recv().await,
        SnPacket::ConnAck {
            return_code: return_code::REJECTED_CONGESTION
        }
    );
    // The owner of the stored session can still come back.
    a.send(&connect_packet("persisted", false)).await;
    assert_eq!(a.recv().await, SnPacket::ConnAck { return_code: 0 });
}

#[tokio::test]
async fn pingreq_from_an_unknown_client_is_answered_with_disconnect() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let c = SnClient::new(t.gw).await;
    c.send(&SnPacket::PingReq { client_id: None }).await;
    assert_eq!(c.recv().await, SnPacket::Disconnect { duration: None });
}

#[tokio::test]
async fn qos0_publish_to_an_unknown_topic_id_is_rejected() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let c = SnClient::new(t.gw).await;
    c.connect("lost-ids", 60).await;
    c.send(&sn_publish(0, TopicIdType::Normal, 77, 0, b"x"))
        .await;
    assert_eq!(
        c.recv().await,
        SnPacket::PubAck {
            topic_id: 77,
            msg_id: 0,
            return_code: return_code::REJECTED_INVALID_TOPIC_ID
        }
    );
}

#[tokio::test]
async fn overlong_topic_names_are_rejected() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let c = SnClient::new(t.gw).await;
    c.connect("long-topics", 60).await;
    c.send(&SnPacket::Register {
        topic_id: 0,
        msg_id: 1,
        topic_name: "a/".repeat(400),
    })
    .await;
    assert_eq!(
        c.recv().await,
        SnPacket::RegAck {
            topic_id: 0,
            msg_id: 1,
            return_code: return_code::REJECTED_INVALID_TOPIC_ID
        }
    );
}

#[tokio::test]
async fn subscription_topic_id_is_used_for_delivery() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let c = SnClient::new(t.gw).await;
    c.connect("sub-ids", 60).await;
    // The topic is also predefined (id 2); a subscription by name still uses the id in SUBACK.
    let SnPacket::SubAck {
        topic_id,
        return_code: 0,
        ..
    } = c.subscribe_name("uav/drone_01/commands", 0, 1).await
    else {
        panic!("expected SUBACK")
    };
    assert_ne!(topic_id, 0);

    let mut gcs = connect(t.broker.addr, v3("gcs-subid")).await;
    gcs.publish(msg("uav/drone_01/commands", b"go", QoS::AtMostOnce))
        .await
        .unwrap();
    let SnPacket::Publish {
        topic_id_type: TopicIdType::Normal,
        topic_id: delivered,
        ..
    } = c.recv().await
    else {
        panic!("expected PUBLISH with the registered topic id")
    };
    assert_eq!(delivered, topic_id);
}

#[tokio::test]
async fn puback_invalid_topic_id_makes_the_gateway_register_again() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let c = SnClient::new(t.gw).await;
    c.connect("forgetful", 60).await;
    assert!(matches!(
        c.subscribe_name("fleet/#", 1, 1).await,
        SnPacket::SubAck { return_code: 0, .. }
    ));
    let mut gcs = connect(t.broker.addr, v3("gcs-forget")).await;
    gcs.publish(msg("fleet/beta", b"hello", QoS::AtLeastOnce))
        .await
        .unwrap();

    for round in 0..2 {
        let SnPacket::Register {
            topic_id,
            msg_id,
            topic_name,
        } = c.recv().await
        else {
            panic!("round {round}: expected REGISTER")
        };
        assert_eq!(topic_name, "fleet/beta");
        c.send(&SnPacket::RegAck {
            topic_id,
            msg_id,
            return_code: 0,
        })
        .await;
        let SnPacket::Publish {
            topic_id: pub_id,
            msg_id,
            data,
            ..
        } = c.recv().await
        else {
            panic!("round {round}: expected PUBLISH")
        };
        assert_eq!(&data[..], b"hello");
        // First round: the client claims it lost the registration.
        let rc = if round == 0 {
            return_code::REJECTED_INVALID_TOPIC_ID
        } else {
            0
        };
        c.send(&SnPacket::PubAck {
            topic_id: pub_id,
            msg_id,
            return_code: rc,
        })
        .await;
    }
    assert!(c.recv_timeout(QUIET).await.is_none());
}

#[tokio::test]
async fn keep_alive_above_the_broker_maximum_is_rejected() {
    let t = sn_setup(AclEngine::new(true), |_| {}).await;
    let c = SnClient::new(t.gw).await;
    c.send(&SnPacket::Connect {
        will: false,
        clean_session: true,
        duration: u16::MAX,
        client_id: "forever".into(),
    })
    .await;
    assert_eq!(
        c.recv().await,
        SnPacket::ConnAck {
            return_code: return_code::REJECTED_NOT_SUPPORTED
        }
    );
}

#[tokio::test]
async fn sn_clients_cannot_replace_an_offline_mqtt_session_of_another_user() {
    let acl = AclEngine::new(false);
    acl.load_from_acl_file("config/acl.conf").await.unwrap();
    let t = sn_setup(acl, |cfg| cfg.acl_user = "sn_gateway".into()).await;

    // A persistent MQTT session owned by dev_sarah, currently offline.
    let mut conn = v5("plc-7").with_credentials("dev_sarah", "sarah_dev_pass");
    conn.properties = wolf_mqtt::protocol::Properties(vec![
        wolf_mqtt::protocol::Property::SessionExpiryInterval(600),
    ]);
    connect(t.broker.addr, conn)
        .await
        .disconnect()
        .await
        .unwrap();

    // An (unauthenticated) MQTT-SN client claiming the same ClientID is refused.
    let sn = SnClient::new(t.gw).await;
    sn.send(&connect_packet("plc-7", true)).await;
    assert_eq!(
        sn.recv().await,
        SnPacket::ConnAck {
            return_code: return_code::REJECTED_CONGESTION
        }
    );
    let kept = t.broker.ctx.session_by_client_id("plc-7").unwrap();
    assert_eq!(kept.transport, wolf_mqtt::session::Transport::Mqtt);
    assert_eq!(kept.user().username, "dev_sarah");
}
