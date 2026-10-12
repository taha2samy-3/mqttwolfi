### 🔒 Empirical MQTT over TLS / mTLS Benchmark Comparison

| Broker | Cryptographic Engine | TLS Handshake | Throughput (msgs/sec) | Bandwidth | Mean Latency | p99 Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **WolfiMQ** | wolfSSL Native / TLS 1.3 | `64.08 ms` | **75767.68 msgs/sec** | `9.25 MB/s` | `13.20 µs` | `23.76 µs` |

*All metrics measured under active TLS 1.3 / mTLS mutual certificate authentication.*
