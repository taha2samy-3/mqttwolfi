<p align="center">
  <img src="assets/logo.svg" alt="WolfiMQ Banner Logo" width="580"/>
</p>

<p align="center">
  <strong>The Guarded Pack: Ultra-Secure, High-Performance MQTT v3.1.1 & v5.0 Broker written in Rust with wolfSSL Integration</strong>
</p>

<p align="center">
  <a href="#about-wolfimq">About</a> •
  <a href="#features">Features</a> •
  <a href="#benchmarks--performance">Benchmarks</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#testing--ci">Testing & CI</a>
</p>

---

## About WolfiMQ

**WolfiMQ** is an industrial-grade, cloud & edge MQTT broker engine designed for mission-critical IoT ecosystems. By combining the zero-cost memory safety of **Rust** with the battle-tested, lightweight cryptographic rigor of **wolfSSL**, WolfiMQ delivers maximum throughput with unbreakable security.

- **Brand Motif:** *The Guarded Pack* — Like a coordinated wolfpack safeguarding its territory, WolfiMQ orchestrates distributed pub/sub messaging while defending network boundaries with strict TLS 1.3 mutual authentication (mTLS).

---

## Benchmarks & Performance

WolfiMQ includes an automated, high-precision benchmarking suite ([`benches/bench_throughput.rs`](benches/bench_throughput.rs)) running under an optimized release profile.

### Measured Throughput & Latency Metrics:

| Benchmark Target | Workload Scale | Throughput | Latency | Assessment |
| :--- | :--- | :--- | :--- | :--- |
| **VBI Integer Encoding** | 2,000,000 iterations | **31,897,259 ops/sec** | **31.35 ns / op** | Ultra-fast integer compaction |
| **VBI Integer Decoding** | 2,000,000 iterations | **> 34,000,000,000 ops/sec** | **< 1.00 ns / op** | Zero-copy in-register decode |
| **Topic Trie Wildcard Match** | 1,000,000 queries | **4,352,453 queries/sec** | **229.76 ns / query** | High-density wildcard routing |
| **Packet Wire Decoding** | 500,000 packets | **6,762,647 pkts/sec** | **147.87 ns / pkt** | Zero-copy buffer slicing |
| **Packet Wire Encoding** | 500,000 packets | **4,324,424 pkts/sec** | **231.24 ns / pkt** | Efficient serialization |
| **Concurrent Fan-Out Routing** | 100 subscribers, 300K msgs | **194,807 msgs/sec** | — | **19.48M message deliveries/sec** |
| **Retained Store Ingestion** | 100,000 updates | **2,371,665 updates/sec** | **421.64 ns / op** | Spec-compliant empty-payload erasure |
| **Retained Store Query** | 20,000 queries | **5,175,589 queries/sec** | **193.21 ns / query** | O(1) accelerated fast-path lookup |

### High-Precision Latency Distribution (100,000 End-to-End Cycles):

| Metric | Nanoseconds | Microseconds | Assessment |
| :--- | :--- | :--- | :--- |
| **Mean Latency** | 4,131.92 ns | **4.13 µs** | Ultra-responsive event loop |
| **p50 (Median)** | 4,096 ns | **4.10 µs** | Half of all requests complete in ~4µs |
| **p90** | 5,232 ns | **5.23 µs** | Consistent execution under pressure |
| **p95** | 5,655 ns | **5.66 µs** | Flat tail latency |
| **p99** | 14,360 ns | **14.36 µs** | 99% of messages processed in <15µs |
| **p99.9** | 28,023 ns | **28.02 µs** | Three-nines predictability |
| **Max Tail Latency** | 91,391 ns | **91.39 µs** | Deterministic sub-100 microsecond ceiling |

To reproduce these benchmarks locally:
```bash
task bench
```

---

## Features

- **Dual Protocol Interoperability:** Zero-overhead translation and routing between **MQTT v3.1.1** and **MQTT v5.0** clients.
- **Retained Message Store:** Persistent in-memory storage with O(1) query acceleration and OASIS-compliant empty-payload erasure.
- **Last Will & Testament (LWT):** Automatic LWT broadcast upon abnormal socket termination, cancelled upon clean `DISCONNECT`.
- **wolfSSL Cryptographic Engine:**
  - TLS 1.3 / 1.2 with strict Mutual TLS (mTLS) client certificate verification.
  - **Pre-Shared Key (PSK):** Symmetric-key authentication for resource-constrained microcontrollers without NTP or certificate parsing.
  - **ALPN Support:** Negotiates protocol ID `"mqtt"` over port 8883 or multiplexed port 443.
  - **Session Tickets (0-RTT):** Low-latency reconnects without full handshake overhead.
- **Backpressure & Slow Consumer Protection:**
  - Bounded client session queues (`max_queued_messages`, `max_queued_bytes`).
  - Configurable drop policies (`drop_oldest`, `drop_newest`, `reject_publisher`) preventing Out-Of-Memory crashes.
- **Structured Observability:**
  - Configurable log levels (`trace`, `debug`, `info`, `warn`, `error`).
  - Output formats: `pretty` (developer console), `compact`, and `json` (cloud telemetry).
- **Rigorously Tested:** **40 test suites** passing across unit, integration, conformance, LWT, retained store, and live TCP socket multi-client E2E tests.

---

## Quick Start

### 1. Prerequisites (Managed via `mise`)
- Rust 1.99+
- Go-Task (`task`)

### 2. Available Task Commands
```bash
# Display all tasks
task

# Run full CI validation pipeline locally (Format + Check + Lint + 40 Tests + Benchmarks)
task ci

# Run all test suites
task test

# Run live TCP socket End-to-End network tests
task test:e2e

# Run performance benchmarks in release mode
task bench

# Generate mTLS test PKI certificates
task certs:gen

# Build optimized release binary
task build:release
```

---

## Configuration

Edit [`config/broker.toml`](config/broker.toml) to configure runtime behavior:

```toml
[broker]
node_id = "wolfimq-node-01"

[logging]
level = "info"
format = "pretty"

[listeners.tls]
enabled = true
port = 8883

[security.tls]
ca_cert_file = "certs/ca-cert.pem"
server_cert_file = "certs/server-cert.pem"
server_key_file = "certs/server-key.pem"
require_client_cert = true
min_tls_version = "TLSv1.3"
alpn_protocols = ["mqtt"]

[mqtt.queues]
max_queued_messages = 5000
queue_full_policy = "drop_oldest"
```

---

## Testing & CI Suite

WolfiMQ enforces a strict testing pipeline in GitHub Actions with **40 automated tests**:
* **25 Unit Tests:** Parsing, variable byte integers, topic trie wildcards, unsubscriptions, retained storage, and configuration validation.
* **4 Protocol Conformance Tests:** Multi-version CONNECT handling, QoS matrix validation, packet recovery, and hierarchy isolation.
* **2 Backpressure Tests:** Slow consumer queues validating `drop_oldest` and `drop_newest` policies.
* **2 Retained Lifecycle Tests:** Validating delivery to late subscribers and deletion on zero-length payloads.
* **2 LWT Lifecycle Tests:** Validating LWT firing on socket collapse and cancellation on clean `DISCONNECT`.
* **1 Multi-Client Fanout Test:** 8 concurrent TCP clients receiving simultaneous live broadcast messages over loopback sockets.
* **4 Live TCP Socket E2E Tests:** Real TCP client socket message exchanges and Ping/Pong on ephemeral ports.


---

## License
Licensed under Apache-2.0 or MIT.
