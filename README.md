<p align="center">
  <img src="assets/logo.svg" alt="WolfiMQ Banner Logo" width="580"/>
</p>

<p align="center">
  <strong>The Guarded Pack: Ultra-Secure, High-Performance MQTT v3.1.1 & v5.0 Broker written in Rust with wolfSSL Integration</strong>
</p>

<p align="center">
  <a href="#about-wolfimq">About WolfiMQ</a> •
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#testing--rigor">Testing & CI</a>
</p>

---

## About WolfiMQ

**WolfiMQ** is an industrial-grade, cloud & edge MQTT broker engine designed for mission-critical IoT ecosystems. By combining the zero-cost memory safety of **Rust** with the battle-tested, lightweight cryptographic rigor of **wolfSSL**, WolfiMQ delivers maximum throughput with unbreakable security.

- **Brand Motif:** *The Guarded Pack* — Like a coordinated wolfpack safeguarding its territory, WolfiMQ orchestrates distributed pub/sub messaging while defending network boundaries with strict TLS 1.3 mutual authentication (mTLS).

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
- **Rigorously Tested:** 28+ unit, integration, and backpressure test suites integrated with `Taskfile` and GitHub Actions CI.

---

## Quick Start

### 1. Prerequisites (Managed via `mise`)
- Rust 1.99+
- Go-Task (`task`)

### 2. Available Task Commands
```bash
# Display all tasks
task

# Run full CI validation pipeline locally
task ci

# Run all 28+ unit and integration tests
task test

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

## License
Licensed under Apache-2.0 or MIT.
