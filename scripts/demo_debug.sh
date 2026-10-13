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

port_in_use() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# 2. Refuse to start when another broker already uses the ports (it is not ours to stop).
for port in 1883 8883; do
    if port_in_use "${port}"; then
        echo -e "${RED}Port ${port} is already in use (another MQTT broker?). Stop it and retry.${RESET}"
        exit 1
    fi
done

# 3. Build, then start WolfiMQ in DEBUG mode in the background
echo -e "${BOLD}==> [1/2] Building and starting WolfiMQ in DEBUG mode...${RESET}"
cargo build --bins
# The sample configuration keeps plain TCP disabled; enable it on loopback for the demo.
WOLFIMQ_LISTENERS__TCP__ENABLED=true WOLFIMQ_LISTENERS__TCP__BIND_ADDRESS=127.0.0.1 \
RUST_LOG="wolf_mqtt=debug,wolf_broker=debug,info" ./target/debug/wolf-broker --config config/broker.toml \
    > >(while IFS= read -r line; do echo -e "${MAGENTA}[BROKER-LOG]${RESET} $line"; done) 2>&1 &
BROKER_PID=$!

echo -e "    Broker PID: ${BOLD}${BROKER_PID}${RESET}"
echo -e "    Waiting for the TCP listener on 127.0.0.1:1883..."

READY=false
for _ in {1..40}; do
    if port_in_use 1883; then
        READY=true
        break
    fi
    if ! kill -0 "${BROKER_PID}" 2>/dev/null; then
        break
    fi
    sleep 0.25
done

if [ "$READY" = false ]; then
    echo -e "${RED}The broker did not start listening on 127.0.0.1:1883; see the log above.${RESET}"
    exit 1
fi

echo -e "${GREEN}✔ Broker is listening on TCP 127.0.0.1:1883 and TLS 8883${RESET}\n"

# 4. Run the interactive protocol traffic simulation
echo -e "${BOLD}==> [2/2] Launching Protocol Traffic Simulator...${RESET}"
./target/debug/wolf-simulate "$@"

echo -e "\n${GREEN}✔ Protocol simulation completed successfully!${RESET}"
