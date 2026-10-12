### 🔒 Empirical MQTT over TLS 1.3 / mTLS High-Load Benchmark Comparison

| Broker | Cryptographic Engine | Concurrency | TLS Handshake | Throughput (msgs/sec) | Bandwidth | Mean Latency | p90 Latency | p99 Latency | Max Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **WolfiMQ** | wolfSSL Native / TLS 1.3 | `8 clients` | `64.97 ms` | **157583.04 msgs/sec** | `19.24 MB/s` | `14068.47 µs` | `17493.36 µs` | `52782.21 µs` | `53858.34 µs` |

*Standardized Conditions: RFC 8446 TLS 1.3, Mutual TLS (mTLS), identical payload buffers, identical network loopback, zero message drops.*
