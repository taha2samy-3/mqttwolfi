### 🔒 Empirical MQTT over TLS 1.3 / mTLS High-Load Benchmark Comparison

| Broker | Cryptographic Engine | Concurrency | TLS Handshake | Throughput (msgs/sec) | Bandwidth | Mean Latency | p90 Latency | p99 Latency | Max Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **WolfiMQ** | wolfSSL Native / TLS 1.3 | `8 clients` | `57.37 ms` | **172436.95 msgs/sec** | `21.05 MB/s` | `12677.91 µs` | `47886.78 µs` | `50538.35 µs` | `50739.74 µs` |

*Standardized Conditions: RFC 8446 TLS 1.3, Mutual TLS (mTLS), identical payload buffers, identical network loopback, zero message drops.*
