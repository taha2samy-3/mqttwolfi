//! MQTT v5.0 behaviour over a live TCP listener.

mod common;

use bytes::Bytes;
use common::*;
use std::time::Duration;
use wolf_mqtt::auth::{AclEngine, AclRule, Permission, UserAccount};
use wolf_mqtt::broker::BrokerOptions;
use wolf_mqtt::client::RawClient;
use wolf_mqtt::protocol::{
    reason, MqttPacket, Properties, Property, PublishPacket, QoS, RetainHandling,
    SubscriptionOptions,
};

fn with_props(mut c: wolf_mqtt::ConnectPacket, props: Vec<Property>) -> wolf_mqtt::ConnectPacket {
    c.properties = Properties(props);
    c
}

#[tokio::test]
async fn binary_payloads_survive_cross_version_delivery() {
    // Regression: v5 subscribers used to receive v3.1.1-framed PUBLISH packets, losing bytes.
    let b = open_broker().await;
    let mut sub5 = connect(b.addr, v5("bin-v5")).await;
    let mut sub3 = connect(b.addr, v3("bin-v3")).await;
    sub5.subscribe("bin/#", QoS::AtLeastOnce).await.unwrap();
    sub3.subscribe("bin/#", QoS::AtLeastOnce).await.unwrap();
    let payload: &'static [u8] = &[0x00, 0xAA, 0x26, 0x00, 0xFF];

    let mut pub3 = connect(b.addr, v3("bin-pub3")).await;
    pub3.publish(msg("bin/a", payload, QoS::AtLeastOnce))
        .await
        .unwrap();
    let mut pub5 = connect(b.addr, v5("bin-pub5")).await;
    pub5.publish(msg("bin/b", payload, QoS::AtMostOnce))
        .await
        .unwrap();

    for sub in [&mut sub5, &mut sub3] {
        for topic in ["bin/a", "bin/b"] {
            let p = next_publish(sub).await;
            assert_eq!(p.topic, topic);
            assert_eq!(&p.payload[..], payload);
        }
    }
}

#[tokio::test]
async fn publish_properties_are_forwarded_to_v5_subscribers() {
    let b = open_broker().await;
    let mut sub = connect(b.addr, v5("props-sub")).await;
    sub.subscribe("req/#", QoS::AtMostOnce).await.unwrap();
    let mut legacy = connect(b.addr, v3("props-legacy")).await;
    legacy.subscribe("req/#", QoS::AtMostOnce).await.unwrap();

    let props = Properties(vec![
        Property::PayloadFormatIndicator(1),
        Property::ContentType("application/json".into()),
        Property::ResponseTopic("resp/1".into()),
        Property::CorrelationData(Bytes::from_static(b"\x01\x02")),
        Property::UserProperty("trace".into(), "abc".into()),
    ]);
    let mut publ = connect(b.addr, v5("props-pub")).await;
    publ.publish(msg("req/x", b"{}", QoS::AtMostOnce).with_properties(props.clone()))
        .await
        .unwrap();

    let p = next_publish(&mut sub).await;
    for expected in props.iter() {
        assert!(
            p.properties.iter().any(|x| x == expected),
            "missing {expected:?}"
        );
    }
    let p = next_publish(&mut legacy).await;
    assert_eq!(&p.payload[..], b"{}");
}

#[tokio::test]
async fn message_expiry_is_enforced_and_remaining_time_forwarded() {
    let b = open_broker().await;
    let persistent = with_props(v5("exp-sub"), vec![Property::SessionExpiryInterval(60)]);
    let mut c = connect(b.addr, persistent.clone()).await;
    c.subscribe("exp/#", QoS::AtLeastOnce).await.unwrap();
    c.disconnect().await.unwrap();

    let mut publ = connect(b.addr, v5("exp-pub")).await;
    let short = msg("exp/short", b"s", QoS::AtLeastOnce)
        .with_properties(Properties(vec![Property::MessageExpiryInterval(1)]));
    let long = msg("exp/long", b"l", QoS::AtLeastOnce)
        .with_properties(Properties(vec![Property::MessageExpiryInterval(100)]));
    publ.publish(short).await.unwrap();
    publ.publish(long).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut resume = persistent;
    resume.clean_start = false;
    let mut c = connect(b.addr, resume).await;
    let p = next_publish(&mut c).await;
    assert_eq!(p.topic, "exp/long", "expired message must not be delivered");
    let remaining = p.properties.message_expiry_interval().unwrap();
    assert!(
        (90..=99).contains(&remaining),
        "remaining expiry {remaining}"
    );
    assert_no_publish(&mut c).await;
}

#[tokio::test]
async fn topic_aliases_from_clients() {
    let b = open_broker().await;
    let mut sub = connect(b.addr, v5("alias-sub")).await;
    sub.subscribe("alias/#", QoS::AtMostOnce).await.unwrap();
    let mut publ = connect(b.addr, v5("alias-pub")).await;

    let set = msg("alias/long/topic", b"1", QoS::AtMostOnce)
        .with_properties(Properties(vec![Property::TopicAlias(3)]));
    publ.publish(set).await.unwrap();
    let reuse = PublishPacket::new("", Bytes::from_static(b"2"))
        .with_properties(Properties(vec![Property::TopicAlias(3)]));
    publ.publish(reuse).await.unwrap();
    for payload in [b"1", b"2"] {
        let p = next_publish(&mut sub).await;
        assert_eq!(p.topic, "alias/long/topic");
        assert_eq!(&p.payload[..], payload);
        assert!(
            p.properties.topic_alias().is_none(),
            "client aliases must not be forwarded"
        );
    }

    // An alias above the advertised maximum is a protocol violation.
    let bad = msg("alias/x", b"3", QoS::AtMostOnce)
        .with_properties(Properties(vec![Property::TopicAlias(1000)]));
    publ.publish(bad).await.unwrap();
    let got = publ.wait_closed(Duration::from_secs(2)).await.unwrap();
    assert!(
        got.contains(&MqttPacket::disconnect(reason::TOPIC_ALIAS_INVALID)),
        "{got:?}"
    );
}

#[tokio::test]
async fn subscription_identifiers_and_options() {
    let b = open_broker().await;
    let mut c = connect(b.addr, v5("opts")).await;

    // Subscription identifier.
    let codes = c
        .subscribe_with(
            vec![("ids/#".into(), SubscriptionOptions::new(QoS::AtMostOnce))],
            Properties(vec![Property::SubscriptionIdentifier(42)]),
        )
        .await
        .unwrap();
    assert_eq!(codes, vec![0]);

    // No Local: our own publish on this filter is not echoed back.
    let mut no_local = SubscriptionOptions::new(QoS::AtMostOnce);
    no_local.no_local = true;
    c.subscribe_with(vec![("echo/#".into(), no_local)], Properties::new())
        .await
        .unwrap();

    c.publish(msg("ids/1", b"x", QoS::AtMostOnce))
        .await
        .unwrap();
    let p = next_publish(&mut c).await;
    assert_eq!(
        p.properties.subscription_identifiers().collect::<Vec<_>>(),
        vec![42]
    );
    c.publish(msg("echo/1", b"me", QoS::AtMostOnce))
        .await
        .unwrap();
    assert_no_publish(&mut c).await;
}

#[tokio::test]
async fn retain_as_published_and_retain_handling() {
    let b = open_broker().await;
    let mut publ = connect(b.addr, v5("rh-pub")).await;
    publ.publish(msg("rh/t", b"stored", QoS::AtMostOnce).with_retain(true))
        .await
        .unwrap();

    let mut c = connect(b.addr, v5("rh-sub")).await;
    let mut rap = SubscriptionOptions::new(QoS::AtMostOnce);
    rap.retain_as_published = true;
    rap.retain_handling = RetainHandling::SendIfNew;
    c.subscribe_with(vec![("rh/t".into(), rap)], Properties::new())
        .await
        .unwrap();
    assert!(
        next_publish(&mut c).await.retain,
        "retained message on new subscription"
    );
    // Re-subscribing with SendIfNew does not resend retained messages.
    c.subscribe_with(vec![("rh/t".into(), rap)], Properties::new())
        .await
        .unwrap();
    assert_no_publish(&mut c).await;

    // Retain As Published keeps the RETAIN flag on live messages.
    publ.publish(msg("rh/t", b"live", QoS::AtMostOnce).with_retain(true))
        .await
        .unwrap();
    let p = next_publish(&mut c).await;
    assert!(p.retain && &p.payload[..] == b"live");

    // Retain Handling 2: never send retained messages.
    let mut c2 = connect(b.addr, v5("rh-sub2")).await;
    let mut none = SubscriptionOptions::new(QoS::AtMostOnce);
    none.retain_handling = RetainHandling::DoNotSend;
    c2.subscribe_with(vec![("rh/t".into(), none)], Properties::new())
        .await
        .unwrap();
    assert_no_publish(&mut c2).await;
}

#[tokio::test]
async fn shared_subscriptions_split_messages_between_members() {
    let b = open_broker().await;
    let mut m1 = connect(b.addr, v5("share-1")).await;
    let mut m2 = connect(b.addr, v5("share-2")).await;
    let mut all = connect(b.addr, v5("share-all")).await;
    assert_eq!(
        m1.subscribe("$share/workers/jobs/+", QoS::AtLeastOnce)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        m2.subscribe("$share/workers/jobs/+", QoS::AtLeastOnce)
            .await
            .unwrap(),
        1
    );
    all.subscribe("jobs/+", QoS::AtMostOnce).await.unwrap();

    let mut publ = connect(b.addr, v5("share-pub")).await;
    for i in 0..10u8 {
        publ.publish(PublishPacket::new("jobs/run", Bytes::from(vec![i])))
            .await
            .unwrap();
    }
    let mut seen = Vec::new();
    for c in [&mut m1, &mut m2] {
        while let Ok(Some(MqttPacket::Publish(p))) = c.recv_timeout(QUIET).await {
            seen.push(p.payload[0]);
        }
    }
    seen.sort_unstable();
    assert_eq!(
        seen,
        (0..10).collect::<Vec<u8>>(),
        "each message goes to exactly one member"
    );
    for _ in 0..10 {
        next_publish(&mut all).await;
    }
}

#[tokio::test]
async fn receive_maximum_limits_unacknowledged_deliveries() {
    let b = open_broker().await;
    let mut sub = connect(
        b.addr,
        with_props(v5("rm-sub"), vec![Property::ReceiveMaximum(2)]),
    )
    .await;
    sub.subscribe("rm/#", QoS::AtLeastOnce).await.unwrap();
    let mut publ = connect(b.addr, v5("rm-pub")).await;
    for i in 0..5u8 {
        publ.publish(
            PublishPacket::new("rm/x", Bytes::from(vec![i])).with_qos(QoS::AtLeastOnce, None),
        )
        .await
        .unwrap();
    }
    let mut inflight = Vec::new();
    while let Ok(Some(MqttPacket::Publish(p))) = sub.recv_timeout(QUIET).await {
        inflight.push(p);
    }
    assert_eq!(
        inflight.len(),
        2,
        "only Receive Maximum messages may be unacknowledged"
    );
    sub.ack_publish(&inflight[0]).await.unwrap();
    let next = sub
        .expect(|p| matches!(p, MqttPacket::Publish(_)))
        .await
        .unwrap();
    let MqttPacket::Publish(next) = next else {
        unreachable!()
    };
    assert_eq!(&next.payload[..], &[2]);
}

#[tokio::test]
async fn client_maximum_packet_size_is_respected() {
    let b = open_broker().await;
    let mut sub = connect(
        b.addr,
        with_props(v5("mps-sub"), vec![Property::MaximumPacketSize(64)]),
    )
    .await;
    sub.subscribe("mps/#", QoS::AtMostOnce).await.unwrap();
    let mut publ = connect(b.addr, v5("mps-pub")).await;
    publ.publish(PublishPacket::new("mps/big", Bytes::from(vec![7u8; 200])))
        .await
        .unwrap();
    publ.publish(PublishPacket::new("mps/small", Bytes::from_static(b"ok")))
        .await
        .unwrap();
    assert_eq!(next_publish(&mut sub).await.topic, "mps/small");
}

#[tokio::test]
async fn session_expiry_resume_and_expiration() {
    let b = open_broker().await;
    let short = with_props(v5("short-lived"), vec![Property::SessionExpiryInterval(1)]);
    let mut c = connect(b.addr, short.clone()).await;
    c.subscribe("se/#", QoS::AtLeastOnce).await.unwrap();
    c.disconnect().await.unwrap();

    let mut publ = connect(b.addr, v5("se-pub")).await;
    publ.publish(msg("se/1", b"kept", QoS::AtLeastOnce))
        .await
        .unwrap();

    let mut resume = short.clone();
    resume.clean_start = false;
    let (mut c, ack) = RawClient::connect(b.addr, resume.clone()).await.unwrap();
    assert!(ack.session_present);
    assert_eq!(&next_publish(&mut c).await.payload[..], b"kept");
    c.disconnect().await.unwrap();

    // After the expiry interval (plus the housekeeping tick) the session is gone.
    tokio::time::sleep(Duration::from_millis(2600)).await;
    let (_, ack) = RawClient::connect(b.addr, resume).await.unwrap();
    assert!(!ack.session_present);
}

#[tokio::test]
async fn connack_assigns_client_id_and_server_keep_alive() {
    let mut options = BrokerOptions::permissive();
    options.max_keep_alive_sec = 30;
    let b = start_broker(options, AclEngine::new(true)).await;
    let (_, ack) = RawClient::connect(b.addr, v5("").with_keep_alive(0))
        .await
        .unwrap();
    assert_eq!(ack.reason_code, 0);
    assert!(ack
        .properties
        .assigned_client_identifier()
        .is_some_and(|id| !id.is_empty()));
    assert!(ack
        .properties
        .iter()
        .any(|p| *p == Property::ServerKeepAlive(30)));
    assert!(ack.properties.maximum_packet_size().is_some());
}

#[tokio::test]
async fn authorization_reason_codes() {
    let acl = AclEngine::new(false);
    acl.add_user(UserAccount::new_custom(
        "limited",
        "pw",
        vec![
            AclRule::new("allowed/#", Permission::ReadWrite),
            AclRule::new("readonly/#", Permission::Read),
        ],
    ))
    .await;
    let b = start_broker(BrokerOptions::permissive(), acl).await;

    let (_, ack) = RawClient::connect(b.addr, v5("x").with_credentials("limited", "bad"))
        .await
        .unwrap();
    assert_eq!(ack.reason_code, reason::BAD_USER_NAME_OR_PASSWORD);
    let (_, ack) = RawClient::connect(b.addr, v5("anon")).await.unwrap();
    assert_eq!(ack.reason_code, reason::NOT_AUTHORIZED);

    let mut c = connect(b.addr, v5("lim").with_credentials("limited", "pw")).await;
    assert_eq!(
        c.subscribe("secret/#", QoS::AtMostOnce).await.unwrap(),
        reason::NOT_AUTHORIZED
    );
    assert_eq!(
        c.subscribe("readonly/x", QoS::AtLeastOnce).await.unwrap(),
        1
    );
    assert_eq!(
        c.publish(msg("readonly/x", b"no", QoS::AtLeastOnce))
            .await
            .unwrap(),
        reason::NOT_AUTHORIZED
    );
    assert_eq!(
        c.publish(msg("readonly/x", b"no", QoS::ExactlyOnce))
            .await
            .unwrap(),
        reason::NOT_AUTHORIZED
    );
    assert_eq!(
        c.publish(msg("allowed/x", b"ok", QoS::AtLeastOnce))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        c.unsubscribe(&["readonly/x", "not/subscribed"])
            .await
            .unwrap(),
        vec![reason::SUCCESS, reason::NO_SUBSCRIPTION_EXISTED]
    );
}

#[tokio::test]
async fn will_delay_and_disconnect_with_will() {
    let b = open_broker().await;
    let mut watcher = connect(b.addr, v5("wd-watch")).await;
    watcher.subscribe("wd/#", QoS::AtMostOnce).await.unwrap();

    // Will Delay 2 s with a persistent session: not published immediately.
    let mut will = msg("wd/delayed", b"late", QoS::AtMostOnce);
    will.properties = Properties(vec![Property::WillDelayInterval(2)]);
    let conn = with_props(
        v5("wd-client").with_will(will),
        vec![Property::SessionExpiryInterval(30)],
    );
    let c = connect(b.addr, conn.clone()).await;
    drop(c.into_stream());
    assert_no_publish(&mut watcher).await;
    let p = tokio::time::timeout(Duration::from_secs(4), watcher.recv_publish())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&p.payload[..], b"late");
    assert!(p.properties.will_delay_interval().is_none());

    // Reconnecting before the delay elapses cancels the Will.
    let c = connect(b.addr, conn.clone()).await;
    drop(c.into_stream());
    let mut resumed = conn;
    resumed.clean_start = false;
    let _keep = connect(b.addr, resumed).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_no_publish(&mut watcher).await;

    // DISCONNECT with reason 0x04 publishes the Will immediately.
    let c = connect(
        b.addr,
        v5("wd-04").with_will(msg("wd/now", b"bye", QoS::AtMostOnce)),
    )
    .await;
    let mut c = c;
    c.send(&MqttPacket::disconnect(reason::DISCONNECT_WITH_WILL))
        .await
        .unwrap();
    assert_eq!(&next_publish(&mut watcher).await.payload[..], b"bye");
}

#[tokio::test]
async fn server_sends_disconnect_reason_codes() {
    let mut options = BrokerOptions::permissive();
    options.max_packet_size = 1024;
    let b = start_broker(options, AclEngine::new(true)).await;

    let mut c = connect(b.addr, v5("dc-1")).await;
    c.send(&MqttPacket::Connect(v5("dc-1"))).await.unwrap();
    let got = c.wait_closed(Duration::from_secs(2)).await.unwrap();
    assert!(
        got.contains(&MqttPacket::disconnect(reason::PROTOCOL_ERROR)),
        "{got:?}"
    );

    let mut c = connect(b.addr, v5("dc-2")).await;
    c.send(&MqttPacket::Publish(PublishPacket::new(
        "big",
        Bytes::from(vec![0u8; 4096]),
    )))
    .await
    .unwrap();
    let got = c.wait_closed(Duration::from_secs(2)).await.unwrap();
    assert!(
        got.contains(&MqttPacket::disconnect(reason::PACKET_TOO_LARGE)),
        "{got:?}"
    );

    let mut old = connect(b.addr, v5("dc-3")).await;
    let _new = connect(b.addr, v5("dc-3")).await;
    let got = old.wait_closed(Duration::from_secs(2)).await.unwrap();
    assert!(
        got.contains(&MqttPacket::disconnect(reason::SESSION_TAKEN_OVER)),
        "{got:?}"
    );

    let mut idle = connect(b.addr, v5("dc-4").with_keep_alive(1)).await;
    let got = idle.wait_closed(Duration::from_secs(4)).await.unwrap();
    assert!(
        got.contains(&MqttPacket::disconnect(reason::KEEP_ALIVE_TIMEOUT)),
        "{got:?}"
    );

    // A client may not send Subscription Identifiers in PUBLISH.
    let mut c = connect(b.addr, v5("dc-5")).await;
    c.publish(
        msg("x", b"y", QoS::AtMostOnce)
            .with_properties(Properties(vec![Property::SubscriptionIdentifier(1)])),
    )
    .await
    .unwrap();
    let got = c.wait_closed(Duration::from_secs(2)).await.unwrap();
    assert!(
        got.contains(&MqttPacket::disconnect(reason::PROTOCOL_ERROR)),
        "{got:?}"
    );
}

#[tokio::test]
async fn maximum_qos_and_retain_availability_are_advertised_and_enforced() {
    let mut options = BrokerOptions::permissive();
    options.maximum_qos = QoS::AtLeastOnce;
    options.allow_retained_messages = false;
    let b = start_broker(options, AclEngine::new(true)).await;

    let (mut c, ack) = RawClient::connect(b.addr, v5("caps")).await.unwrap();
    assert!(ack.properties.iter().any(|p| *p == Property::MaximumQoS(1)));
    assert!(ack
        .properties
        .iter()
        .any(|p| *p == Property::RetainAvailable(0)));
    assert_eq!(c.subscribe("caps/#", QoS::ExactlyOnce).await.unwrap(), 1);
    c.send(&MqttPacket::Publish(
        msg("caps/x", b"r", QoS::AtMostOnce).with_retain(true),
    ))
    .await
    .unwrap();
    let got = c.wait_closed(Duration::from_secs(2)).await.unwrap();
    assert!(
        got.contains(&MqttPacket::disconnect(reason::RETAIN_NOT_SUPPORTED)),
        "{got:?}"
    );

    let mut c = connect(b.addr, v5("caps-2")).await;
    let mut m = msg("caps/x", b"q2", QoS::ExactlyOnce);
    m.packet_id = Some(1);
    c.send(&MqttPacket::Publish(m)).await.unwrap();
    let got = c.wait_closed(Duration::from_secs(2)).await.unwrap();
    assert!(got.contains(&MqttPacket::disconnect(0x9B)), "{got:?}");
}

#[tokio::test]
async fn invalid_utf8_with_payload_format_indicator_is_rejected() {
    let b = open_broker().await;
    let mut c = connect(b.addr, v5("pfi")).await;
    let bad = PublishPacket::new("pfi/x", Bytes::from_static(&[0xFF, 0xFE]))
        .with_qos(QoS::AtLeastOnce, None)
        .with_properties(Properties(vec![Property::PayloadFormatIndicator(1)]));
    assert_eq!(
        c.publish(bad).await.unwrap(),
        reason::PAYLOAD_FORMAT_INVALID
    );
}

#[tokio::test]
async fn delayed_will_is_published_when_a_clean_start_ends_the_session() {
    let b = open_broker().await;
    let mut watcher = connect(b.addr, v5("dw-watch")).await;
    watcher.subscribe("dw/#", QoS::AtMostOnce).await.unwrap();
    let mut will = msg("dw/gone", b"bye", QoS::AtMostOnce);
    will.properties = Properties(vec![Property::WillDelayInterval(30)]);
    let conn = with_props(
        v5("dw-client").with_will(will),
        vec![Property::SessionExpiryInterval(60)],
    );
    let _old = connect(b.addr, conn).await;
    // A new connection with Clean Start ends the old session, so its Will is due now.
    let _new = connect(b.addr, v5("dw-client")).await;
    let p = tokio::time::timeout(Duration::from_secs(2), watcher.recv_publish())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&p.payload[..], b"bye");
}
