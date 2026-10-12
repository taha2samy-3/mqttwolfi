#!/usr/bin/env bash
set -euo pipefail

echo "================================================================================"
echo "    Automated TLS Broker Benchmark Runner: WolfiMQ vs. Eclipse Mosquitto        "
echo "================================================================================"

# 1. Ensure test certificates exist
if [ ! -f "certs/server-cert.pem" ] || [ ! -f "certs/ca-cert.pem" ]; then
    echo "==> Generating PKI test certificates..."
    bash scripts/generate_certs.sh
fi

MOSQUITTO_PORT=18883
MOSQUITTO_CONF_DIR="$(mktemp -d)"
MOSQUITTO_CONF="${MOSQUITTO_CONF_DIR}/mosquitto_tls.conf"
MOSQUITTO_PID=""

cleanup() {
    EXIT_CODE=$?
    if [ "${EXIT_CODE}" -ne 0 ] && [ -f "${MOSQUITTO_CONF_DIR}/mosquitto.log" ]; then
        echo "==> Mosquitto log output on failure:"
        cat "${MOSQUITTO_CONF_DIR}/mosquitto.log"
    fi
    if [ -n "${MOSQUITTO_PID}" ]; then
        echo "==> Stopping Mosquitto background process (PID ${MOSQUITTO_PID})..."
        kill -9 "${MOSQUITTO_PID}" 2>/dev/null || true
    fi
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
require_certificate false
allow_anonymous true
log_type all
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
else
    echo "==> Mosquitto binary not installed locally. Running WolfiMQ TLS benchmark alone."
    echo "    (In CI, Mosquitto will be installed via apt-get for side-by-side comparison)."
fi

# 3. Run comparative benchmark binary
SUMMARY_FILE="tls_benchmark_summary.md"
CONCURRENCY="${CONCURRENCY:-8}"
MSG_COUNT="${MSG_COUNT:-10000}"
PAYLOAD_SIZE="${PAYLOAD_SIZE:-128}"

if [ "${HAS_MOSQUITTO}" = true ]; then
    cargo run --release --bin wolf-bench-tls -- \
        --concurrency "${CONCURRENCY}" \
        --count "${MSG_COUNT}" \
        --payload-size "${PAYLOAD_SIZE}" \
        --external-port "${MOSQUITTO_PORT}" \
        --external-name "Eclipse Mosquitto (OpenSSL)" \
        --markdown-output "${SUMMARY_FILE}"
else
    cargo run --release --bin wolf-bench-tls -- \
        --concurrency "${CONCURRENCY}" \
        --count "${MSG_COUNT}" \
        --payload-size "${PAYLOAD_SIZE}" \
        --markdown-output "${SUMMARY_FILE}"
fi

# 4. If running in GitHub Actions, attach to step summary
if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "${SUMMARY_FILE}" ]; then
    echo "==> Exporting results to GitHub Actions Step Summary..."
    cat "${SUMMARY_FILE}" >> "${GITHUB_STEP_SUMMARY}"
fi

echo "================================================================================"
echo "TLS Benchmark completed successfully."
echo "================================================================================"
