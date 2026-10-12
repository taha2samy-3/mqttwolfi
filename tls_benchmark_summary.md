### 🔒 Empirical MQTT over TLS / mTLS Benchmark Comparison

| Broker | Cryptographic Engine | TLS Handshake | Throughput (msgs/sec) | Bandwidth | Mean Latency | p99 Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **WolfiMQ** | wolfSSL Native / TLS 1.3 | `54.11 ms` | **80472.76 msgs/sec** | `9.82 MB/s` | `12.43 µs` | `22.37 µs` |

*All metrics measured under active TLS 1.3 / mTLS mutual certificate authentication.*
