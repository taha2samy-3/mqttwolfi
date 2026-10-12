# Multi-Stage Production Build for WolfiMQ
FROM rust:1.84-bookworm AS builder

WORKDIR /usr/src/wolfimq

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "pub mod lib {}" > src/lib.rs
RUN cargo build --release || true

# Copy full source tree and build optimized release binary
COPY . .
RUN cargo build --release --bin wolf-broker

# Runtime Stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root user
RUN useradd -u 10001 -U -s /bin/false wolfi

WORKDIR /app

COPY --from=builder /usr/src/wolfimq/target/release/wolf-broker /usr/local/bin/wolf-broker
COPY --from=builder /usr/src/wolfimq/config /app/config
RUN mkdir -p /app/certs && chown -R wolfi:wolfi /app

USER wolfi

EXPOSE 1883 8883

ENTRYPOINT ["/usr/local/bin/wolf-broker"]
CMD ["--config", "/app/config/broker.toml"]
