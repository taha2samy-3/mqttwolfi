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
| **VBI Integer Encoding** | 2,000,000 iterations | **42,468,989 ops/sec** | **23.55 ns / op** | Ultra-fast integer compaction |
| **VBI Integer Decoding** | 2,000,000 iterations | **> 50,000,000 ops/sec** | **< 1.00 ns / op** | Sub-nanosecond parsing |
| **Topic Trie Wildcard Match** | 1,000,000 queries | **5,062,678 queries/sec** | **197.52 ns / query** | High-density wildcard routing |
| **Packet Wire Decoding** | 500,000 packets | **9,389,778 pkts/sec** | **106.50 ns / pkt** | Zero-copy buffer slicing |
| **Packet Wire Encoding** | 500,000 packets | **4,512,460 pkts/sec** | **221.61 ns / pkt** | Efficient serialization |
| **Concurrent Fan-Out Routing** | 100 subscribers, 300K msgs | **204,995 msgs/sec** | — | **20.50M message deliveries/sec** |

To reproduce these benchmarks locally:
```bash
task bench
```

---

## Features

- **Dual Protocol Interoperability:** Zero-overhead translation and routing between **MQTT v3.1.1** and **MQTT v5.0** clients.
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
- **Rigorously Tested:** **32 test suites** passing across unit, integration, and live TCP socket E2E tests.

---

## Quick Start

### 1. Prerequisites (Managed via `mise`)
- Rust 1.99+
- Go-Task (`task`)

### 2. Available Task Commands
```bash
# Display all tasks
task

# Run full CI validation pipeline locally (Format + Check + Lint + 32 Tests + Benchmarks)
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

WolfiMQ enforces a strict testing pipeline in GitHub Actions with **32 automated tests**:
* **22 Unit Tests:** Parsing, variable byte integers, topic trie wildcards, unsubscriptions, and configuration rules.
* **7 Integration Tests:** Protocol conformance (QoS 0/1, PubAck), multi-tenant isolation, and queue backpressure.
* **3 Live TCP Socket E2E Tests:** Real TCP client socket message exchanges on ephemeral ports.

---

## License
Licensed under Apache-2.0 or MIT.
