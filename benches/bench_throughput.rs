use bytes::{Bytes, BytesMut};
use std::time::Instant;
use wolf_mqtt::protocol::{
    decode_variable_byte_integer, encode_variable_byte_integer, MqttPacket, PublishPacket, QoS,
};
use wolf_mqtt::routing::TopicTrie;

fn main() {
    println!("================================================================================");
    println!("          WolfiMQ Engine High-Precision Benchmarks & Performance Metrics         ");
    println!("================================================================================\n");

    bench_vbi_codec();
    bench_topic_trie_routing();
    bench_packet_serialization();
    bench_end_to_end_routing_pipeline();

    println!("================================================================================");
    println!("All benchmarks executed successfully under optimized release profile.");
    println!("================================================================================");
}

fn bench_vbi_codec() {
    println!("--- 1. Variable Byte Integer (VBI) Codec Benchmark ---");
    let iterations = 2_000_000;
    let values = [127u32, 16_383, 2_097_151, 268_435_455];

    let mut buf = BytesMut::with_capacity(iterations * 4);
    let start_encode = Instant::now();
    for i in 0..iterations {
        let val = values[i % values.len()];
        let _ = encode_variable_byte_integer(val, &mut buf);
    }
    let encode_duration = start_encode.elapsed();
    let encode_ops_sec = (iterations as f64) / encode_duration.as_secs_f64();
    let encode_ns_op = (encode_duration.as_nanos() as f64) / (iterations as f64);

    let mut read_slice = &buf[..];
    let start_decode = Instant::now();
    for _ in 0..iterations {
        let _ = decode_variable_byte_integer(&mut read_slice);
    }
    let decode_duration = start_decode.elapsed();
    let decode_ops_sec = (iterations as f64) / decode_duration.as_secs_f64();
    let decode_ns_op = (decode_duration.as_nanos() as f64) / (iterations as f64);

    println!("  Iterations      : {} ops", iterations);
    println!(
        "  VBI Encode Speed: {:.2} ops/sec  ({:.2} ns/op)",
        encode_ops_sec, encode_ns_op
    );
    println!(
        "  VBI Decode Speed: {:.2} ops/sec  ({:.2} ns/op)\n",
        decode_ops_sec, decode_ns_op
    );
}

fn bench_topic_trie_routing() {
    println!("--- 2. Topic Trie Wildcard Matching Benchmark ---");
    let mut trie = TopicTrie::new();

    // Populate a realistic industrial hierarchy
    let filters = [
        "factory/+/temperature",
        "factory/zone1/#",
        "sensors/+/vibration",
        "telemetry/#",
        "home/livingroom/thermostat",
        "cars/+/engine/rpm",
        "powergrid/substation3/voltage",
    ];

    for (idx, filter) in filters.iter().enumerate() {
        trie.subscribe(filter, idx).unwrap();
    }

    let test_topics = [
        "factory/zone1/temperature",
        "factory/zone1/machine4/status",
        "sensors/motorA/vibration",
        "telemetry/battery/level",
        "home/livingroom/thermostat",
        "cars/bmw/engine/rpm",
        "unmatched/device/random",
    ];

    let iterations = 1_000_000;
    let start = Instant::now();
    let mut matched_count = 0usize;

    for i in 0..iterations {
        let topic = test_topics[i % test_topics.len()];
        matched_count += trie.matches(topic).len();
    }

    let duration = start.elapsed();
    let ops_sec = (iterations as f64) / duration.as_secs_f64();
    let ns_op = (duration.as_nanos() as f64) / (iterations as f64);

    println!("  Iterations      : {} queries", iterations);
    println!("  Matched Entities: {} total matches", matched_count);
    println!(
        "  Trie Match Speed: {:.2} queries/sec  ({:.2} ns/query)\n",
        ops_sec, ns_op
    );
}

fn bench_packet_serialization() {
    println!("--- 3. MQTT Packet Serialization & Codec Benchmark ---");
    let iterations = 500_000;
    let payload =
        Bytes::from_static(b"{\"temp\": 24.5, \"humidity\": 60.2, \"device\": \"node-01\"}");

    let pub_pkt = MqttPacket::Publish(PublishPacket {
        topic: "factory/assembly/sensor1".into(),
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
        packet_id: Some(1024),
        payload: payload.clone(),
    });

    let mut buf = BytesMut::with_capacity(iterations * 64);
    let start_encode = Instant::now();
    for _ in 0..iterations {
        pub_pkt.encode(&mut buf).unwrap();
    }
    let encode_duration = start_encode.elapsed();
    let encode_ops_sec = (iterations as f64) / encode_duration.as_secs_f64();
    let encode_ns_op = (encode_duration.as_nanos() as f64) / (iterations as f64);

    let mut read_slice = &buf[..];
    let start_decode = Instant::now();
    for _ in 0..iterations {
        let _ = MqttPacket::decode(&mut read_slice).unwrap();
    }
    let decode_duration = start_decode.elapsed();
    let decode_ops_sec = (iterations as f64) / decode_duration.as_secs_f64();
    let decode_ns_op = (decode_duration.as_nanos() as f64) / (iterations as f64);

    println!("  Iterations      : {} packets", iterations);
    println!(
        "  Packet Encode   : {:.2} pkts/sec  ({:.2} ns/pkt)",
        encode_ops_sec, encode_ns_op
    );
    println!(
        "  Packet Decode   : {:.2} pkts/sec  ({:.2} ns/pkt)\n",
        decode_ops_sec, decode_ns_op
    );
}

fn bench_end_to_end_routing_pipeline() {
    println!("--- 4. In-Memory Concurrent Message Routing Pipeline Benchmark ---");
    let mut trie = TopicTrie::new();
    let subscriber_count = 100;
    for id in 0..subscriber_count {
        trie.subscribe("devices/+/data", id).unwrap();
    }

    let iterations = 300_000;
    let start = Instant::now();
    let mut total_routed = 0usize;

    for i in 0..iterations {
        let topic = format!("devices/sensor_{}/data", i % 1000);
        let subscribers = trie.matches(&topic);
        total_routed += subscribers.len();
    }

    let duration = start.elapsed();
    let msgs_sec = (iterations as f64) / duration.as_secs_f64();
    let deliveries_sec = (total_routed as f64) / duration.as_secs_f64();

    println!(
        "  Subscribers     : {} active topic listeners",
        subscriber_count
    );
    println!("  Messages Process: {} messages", iterations);
    println!("  Routing Speed   : {:.2} msgs/sec", msgs_sec);
    println!(
        "  Fan-out Throughput: {:.2} message-deliveries/sec\n",
        deliveries_sec
    );
}
