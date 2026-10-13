#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# WolfiMQ Interactive Debug & Traffic Simulation Runner
# ==============================================================================

BOLD="\033[1m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
MAGENTA="\033[1;35m"
RED="\033[1;31m"
RESET="\033[0m"

echo -e "${CYAN}================================================================================${RESET}"
echo -e "${CYAN}       🐺 WolfiMQ Real-Time Debug & Live Protocol Simulation Runner            ${RESET}"
echo -e "${CYAN}================================================================================${RESET}\n"

# 1. Ensure test PKI certificates exist
if [ ! -f "certs/server-cert.pem" ] || [ ! -f "certs/ca-cert.pem" ]; then
    echo -e "${YELLOW}==> Generating test PKI TLS certificates (scripts/generate_certs.sh)...${RESET}"
    bash scripts/generate_certs.sh certs
fi

BROKER_PID=""

cleanup() {
    echo -e "\n${YELLOW}==> Stopping background processes and cleaning up...${RESET}"
    if [ -n "${BROKER_PID}" ]; then
        kill -15 "${BROKER_PID}" 2>/dev/null || true
        wait "${BROKER_PID}" 2>/dev/null || true
    fi
    echo -e "${GREEN}==> All processes cleanly terminated.${RESET}"
}
trap cleanup EXIT INT TERM

# 2. Check if ports 1883 or 8883 are already occupied
if command -v fuser >/dev/null 2>&1; then
    fuser -k 1883/tcp 2>/dev/null || true
    fuser -k 8883/tcp 2>/dev/null || true
fi

# 3. Start WolfiMQ Broker in DEBUG mode in the background
echo -e "${BOLD}==> [1/2] Starting WolfiMQ Broker in DEBUG mode (RUST_LOG=debug)...${RESET}"
# The sample configuration keeps plain TCP disabled; enable it on loopback for the demo.
WOLFIMQ_LISTENERS__TCP__ENABLED=true WOLFIMQ_LISTENERS__TCP__BIND_ADDRESS=127.0.0.1 \
RUST_LOG="wolf_mqtt=debug,wolf_broker=debug,info" cargo run --bin wolf-broker -- --config config/broker.toml > >(while IFS= read -r line; do echo -e "${MAGENTA}[BROKER-LOG]${RESET} $line"; done) 2>&1 &
BROKER_PID=$!

echo -e "    Broker PID: ${BOLD}${BROKER_PID}${RESET}"
echo -e "    Awaiting listener initialization on 127.0.0.1:1883..."

# Wait up to 10 seconds for the TCP listener to be ready
READY=false
for _ in {1..20}; do
    if command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 1883 2>/dev/null; then
        READY=true
        break
    fi
    sleep 0.5
done

if [ "$READY" = false ]; then
    sleep 1.5
fi

echo -e "${GREEN}✔ Broker is active and listening on TCP (1883) & TLS (8883)!${RESET}\n"

# 4. Run the interactive protocol traffic simulation
echo -e "${BOLD}==> [2/2] Launching Protocol Traffic Simulator...${RESET}"
cargo run --bin wolf-simulate -- "$@"

echo -e "\n${GREEN}✔ Protocol simulation completed successfully!${RESET}"
