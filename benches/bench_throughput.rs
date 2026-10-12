use bytes::{Bytes, BytesMut};
use std::time::Instant;
use wolf_mqtt::protocol::{
    decode_variable_byte_integer, encode_variable_byte_integer, MqttPacket, PublishPacket, QoS,
};
use wolf_mqtt::routing::retained::RetainedStore;
use wolf_mqtt::routing::TopicTrie;

fn main() {
    println!("================================================================================");
    println!("          WolfiMQ Engine High-Precision Benchmarks & Performance Metrics         ");
    println!("================================================================================\n");

    bench_vbi_codec();
    bench_topic_trie_routing();
    bench_packet_serialization();
    bench_end_to_end_routing_pipeline();
    bench_retained_store();
    bench_latency_percentiles();

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

fn bench_retained_store() {
    println!("--- 5. Retained Messages Store Insertion & Query Benchmark ---");
    let mut store = RetainedStore::new();
    let iterations = 100_000;

    // 1. Benchmark Retained Store Updates
    let start_insert = Instant::now();
    for i in 0..iterations {
        let topic = format!("devices/unit_{}/telemetry", i % 5000);
        let packet = PublishPacket {
            topic,
            qos: QoS::AtMostOnce,
            retain: true,
            dup: false,
            packet_id: None,
            payload: Bytes::from_static(b"ACTIVE_ONLINE"),
        };
        store.update(packet);
    }
    let insert_dur = start_insert.elapsed();
    let insert_ops_sec = (iterations as f64) / insert_dur.as_secs_f64();

    // 2. Benchmark Retained Query with Wildcard Filter
    let query_iterations = 20_000;
    let start_query = Instant::now();
    let mut total_matches = 0;
    for _ in 0..query_iterations {
        let matches = store.get_matches_for_filter("devices/unit_42/telemetry");
        total_matches += matches.len();
    }
    let query_dur = start_query.elapsed();
    let query_ops_sec = (query_iterations as f64) / query_dur.as_secs_f64();

    println!("  Retained Entries: {} stored topics", store.count());
    println!("  Insert Speed    : {:.2} updates/sec", insert_ops_sec);
    println!("  Query Speed     : {:.2} queries/sec (total matches: {})\n", query_ops_sec, total_matches);
}

fn bench_latency_percentiles() {
    println!("--- 6. High-Precision Latency Distribution (p50 / p90 / p99 / p99.9 / max) ---");
    let mut trie = TopicTrie::new();
    for i in 0..50 {
        trie.subscribe("iot/sensors/+/temp", i).unwrap();
    }

    let sample_count = 100_000;
    let mut latencies_ns = Vec::with_capacity(sample_count);

    let pub_pkt = MqttPacket::Publish(PublishPacket {
        topic: "iot/sensors/zoneA/temp".into(),
        qos: QoS::AtLeastOnce,
        retain: false,
        dup: false,
        packet_id: Some(101),
        payload: Bytes::from_static(b"26.8"),
    });

    let mut encode_buf = BytesMut::with_capacity(128);
    pub_pkt.encode(&mut encode_buf).unwrap();
    let frozen_bytes = encode_buf.freeze();

    for _ in 0..sample_count {
        let start = Instant::now();

        // 1. Packet Decode
        let mut slice = &frozen_bytes[..];
        let decoded = MqttPacket::decode(&mut slice).unwrap();

        // 2. Trie Route Lookup
        if let MqttPacket::Publish(ref p) = decoded {
            let _ = trie.matches(&p.topic);
        }

        // 3. Packet Re-encode (fanout preparation)
        let mut out_buf = BytesMut::with_capacity(64);
        decoded.encode(&mut out_buf).unwrap();

        let elapsed_ns = start.elapsed().as_nanos() as u64;
        latencies_ns.push(elapsed_ns);
    }

    latencies_ns.sort_unstable();

    let sum: u64 = latencies_ns.iter().sum();
    let mean_ns = (sum as f64) / (sample_count as f64);
    let p50 = latencies_ns[(sample_count as f64 * 0.50) as usize];
    let p90 = latencies_ns[(sample_count as f64 * 0.90) as usize];
    let p95 = latencies_ns[(sample_count as f64 * 0.95) as usize];
    let p99 = latencies_ns[(sample_count as f64 * 0.99) as usize];
    let p999 = latencies_ns[(sample_count as f64 * 0.999) as usize];
    let max = *latencies_ns.last().unwrap();

    println!("  Sample Size     : {} full decode -> route -> encode cycles", sample_count);
    println!("  Mean Latency    : {:.2} ns  ({:.3} µs)", mean_ns, mean_ns / 1_000.0);
    println!("  p50 (Median)    : {} ns  ({:.3} µs)", p50, (p50 as f64) / 1_000.0);
    println!("  p90             : {} ns  ({:.3} µs)", p90, (p90 as f64) / 1_000.0);
    println!("  p95             : {} ns  ({:.3} µs)", p95, (p95 as f64) / 1_000.0);
    println!("  p99             : {} ns  ({:.3} µs)", p99, (p99 as f64) / 1_000.0);
    println!("  p99.9           : {} ns  ({:.3} µs)", p999, (p999 as f64) / 1_000.0);
    println!("  Max Latency     : {} ns  ({:.3} µs)\n", max, (max as f64) / 1_000.0);
}
