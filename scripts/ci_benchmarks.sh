#!/usr/bin/env bash
# Runs the benchmark suites and writes a Markdown report (used by CI and releases).
# Usage: scripts/ci_benchmarks.sh [output.md]      (default: BENCHMARKS.md)
set -euo pipefail

OUT="${1:-BENCHMARKS.md}"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

[ -f certs/server-cert.pem ] || bash scripts/generate_certs.sh certs >/dev/null

echo "==> Micro-benchmarks (codec, routing, retained store, loopback)"
cargo bench --bench wolf-bench | tee "${WORK}/micro.txt"

echo "==> TLS 1.3 throughput (WolfiMQ, and Mosquitto when installed)"
GITHUB_STEP_SUMMARY="" SUMMARY_FILE="${WORK}/tls.md" CONCURRENCY="${CONCURRENCY:-8}" MSG_COUNT="${MSG_COUNT:-20000}" \
    bash scripts/run_ci_tls_benchmark.sh

cpu="$( (lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -1) || true)"
[ -n "${cpu}" ] || cpu="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
cores="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo '?')"

{
    echo "## Benchmark results"
    echo
    echo "| | |"
    echo "| :--- | :--- |"
    echo "| Commit | \`$(git rev-parse --short HEAD 2>/dev/null || echo unknown)\` |"
    echo "| Date (UTC) | $(date -u +%Y-%m-%dT%H:%MZ) |"
    echo "| Machine | ${cpu}, ${cores} vCPU, $(uname -sm) |"
    echo "| Toolchain | $(rustc --version) |"
    echo "| Profile | release (\`lto = \"fat\"\`, \`codegen-units = 1\`) |"
    echo
    cat "${WORK}/tls.md"
    echo
    echo "### Micro-benchmarks"
    echo
    echo '```text'
    { grep -v '^=\+$' "${WORK}/micro.txt" || true; } | sed '/^$/N;/^\n$/D'
    echo '```'
    echo
    echo "> CI runners are shared virtual machines, so absolute numbers vary between runs;"
    echo "> compare results produced on the same runner type. Both brokers use TLS 1.3 with client"
    echo "> certificates, but WolfiMQ runs inside the benchmark process while Mosquitto is a separate"
    echo "> process, so the side-by-side figures are indicative only."
} > "${OUT}"

echo "==> Report written to ${OUT}"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    cat "${OUT}" >> "${GITHUB_STEP_SUMMARY}"
fi
