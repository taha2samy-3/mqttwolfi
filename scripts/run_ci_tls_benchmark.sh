#!/usr/bin/env bash
set -euo pipefail

echo "================================================================================"
echo "  Automated TLS / WebSocket Benchmark Runner: WolfiMQ vs. Eclipse Mosquitto     "
echo "================================================================================"

# 1. Ensure test certificates exist
if [ ! -f "certs/server-cert.pem" ] || [ ! -f "certs/ca-cert.pem" ]; then
    echo "==> Generating PKI test certificates..."
    bash scripts/generate_certs.sh certs
fi

MOSQUITTO_PORT=18883
MOSQUITTO_WSS_PORT=18884
MOSQUITTO_CONF_DIR="$(mktemp -d)"
MOSQUITTO_CONF="${MOSQUITTO_CONF_DIR}/mosquitto_tls.conf"
MOSQUITTO_WSS_CONF="${MOSQUITTO_CONF_DIR}/mosquitto_wss.conf"
MOSQUITTO_PID=""
MOSQUITTO_WSS_PID=""

cleanup() {
    EXIT_CODE=$?
    if [ "${EXIT_CODE}" -ne 0 ] && [ -f "${MOSQUITTO_CONF_DIR}/mosquitto.log" ]; then
        echo "==> Mosquitto log output on failure:"
        cat "${MOSQUITTO_CONF_DIR}/mosquitto.log"
    fi
    for pid in "${MOSQUITTO_PID}" "${MOSQUITTO_WSS_PID}"; do
        if [ -n "${pid}" ]; then
            echo "==> Stopping Mosquitto background process (PID ${pid})..."
            kill -9 "${pid}" 2>/dev/null || true
        fi
    done
    rm -rf "${MOSQUITTO_CONF_DIR}"
}
trap cleanup EXIT

# 2. Check if mosquitto binary is available
HAS_MOSQUITTO=false
if command -v mosquitto >/dev/null 2>&1; then
    HAS_MOSQUITTO=true
    echo "==> Found Mosquitto binary: $(which mosquitto)"
    echo "    Version: $(mosquitto -h | head -n 1)"

    # Create temporary Mosquitto TLS configuration
    cat <<EOF > "${MOSQUITTO_CONF}"
per_listener_settings false
listener ${MOSQUITTO_PORT} 127.0.0.1
cafile $(pwd)/certs/ca-cert.pem
certfile $(pwd)/certs/server-cert.pem
keyfile $(pwd)/certs/server-key.pem
require_certificate true
allow_anonymous true
log_type error
log_type warning
log_dest file ${MOSQUITTO_CONF_DIR}/mosquitto.log
max_queued_messages 0
EOF

    echo "==> Starting Mosquitto with TLS on 127.0.0.1:${MOSQUITTO_PORT}..."
    mosquitto -c "${MOSQUITTO_CONF}" > "${MOSQUITTO_CONF_DIR}/mosquitto.log" 2>&1 &
    MOSQUITTO_PID=$!
    sleep 1

    # Verify Mosquitto is listening
    if ! kill -0 "${MOSQUITTO_PID}" 2>/dev/null; then
        echo "Warning: Mosquitto failed to start. Log output:"
        cat "${MOSQUITTO_CONF_DIR}/mosquitto.log"
        MOSQUITTO_PID=""
        HAS_MOSQUITTO=false
    fi

    # A second instance for MQTT over WebSocket + TLS, so a Mosquitto build without WebSocket
    # support does not affect the TLS comparison. Browsers present no client certificate, so
    # both brokers use server authentication only in this workload.
    cat <<EOF > "${MOSQUITTO_WSS_CONF}"
per_listener_settings false
listener ${MOSQUITTO_WSS_PORT} 127.0.0.1
protocol websockets
cafile $(pwd)/certs/ca-cert.pem
certfile $(pwd)/certs/server-cert.pem
keyfile $(pwd)/certs/server-key.pem
allow_anonymous true
log_type error
log_type warning
log_dest file ${MOSQUITTO_CONF_DIR}/mosquitto_wss.log
max_queued_messages 0
EOF
    echo "==> Starting Mosquitto with WebSocket + TLS on 127.0.0.1:${MOSQUITTO_WSS_PORT}..."
    mosquitto -c "${MOSQUITTO_WSS_CONF}" > "${MOSQUITTO_CONF_DIR}/mosquitto_wss.log" 2>&1 &
    MOSQUITTO_WSS_PID=$!
    sleep 1
    if ! kill -0 "${MOSQUITTO_WSS_PID}" 2>/dev/null; then
        echo "Warning: Mosquitto WebSocket listener failed to start (built without websockets?):"
        cat "${MOSQUITTO_CONF_DIR}/mosquitto_wss.log"
        MOSQUITTO_WSS_PID=""
    fi
else
    echo "==> Mosquitto binary not installed locally. Running WolfiMQ benchmarks alone."
    echo "    (In CI, Mosquitto will be installed via apt-get for side-by-side comparison)."
fi

# 3. Run comparative benchmark binary
SUMMARY_FILE="${SUMMARY_FILE:-tls_benchmark_summary.md}"
CONCURRENCY="${CONCURRENCY:-8}"
MSG_COUNT="${MSG_COUNT:-10000}"
PAYLOAD_SIZE="${PAYLOAD_SIZE:-128}"

cargo build --release --bin wolf-bench-tls
run_bench() { # <transport> <mosquitto port or empty> <markdown file>
    local external=()
    if [ -n "$2" ]; then
        external=(--external-port "$2" --external-name "Eclipse Mosquitto (OpenSSL)")
    fi
    ./target/release/wolf-bench-tls --transport "$1" \
        --concurrency "${CONCURRENCY}" \
        --count "${MSG_COUNT}" \
        --payload-size "${PAYLOAD_SIZE}" \
        "${external[@]}" \
        --markdown-output "$3"
}
TLS_PORT=""
if [ "${HAS_MOSQUITTO}" = true ]; then TLS_PORT="${MOSQUITTO_PORT}"; fi
WSS_PORT=""
if [ -n "${MOSQUITTO_WSS_PID}" ]; then WSS_PORT="${MOSQUITTO_WSS_PORT}"; fi
run_bench tls "${TLS_PORT}" "${MOSQUITTO_CONF_DIR}/tls.md"
run_bench wss "${WSS_PORT}" "${MOSQUITTO_CONF_DIR}/wss.md"
{
    cat "${MOSQUITTO_CONF_DIR}/tls.md"
    echo
    cat "${MOSQUITTO_CONF_DIR}/wss.md"
} > "${SUMMARY_FILE}"

# 4. If running in GitHub Actions, attach to step summary
if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "${SUMMARY_FILE}" ]; then
    echo "==> Exporting results to GitHub Actions Step Summary..."
    cat "${SUMMARY_FILE}" >> "${GITHUB_STEP_SUMMARY}"
fi

echo "================================================================================"
echo "TLS and WebSocket benchmarks completed successfully."
echo "================================================================================"
