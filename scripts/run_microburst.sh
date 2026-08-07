#!/usr/bin/env bash
# Microburst experiment (E2 subset).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== PTT-INT Microburst Experiment ==="
echo ""

BOTTLENECK_RATE="${BOTTLENECK_RATE:-100}"

sudo python3 experiments/run_matrix.py \
    --experiment microburst \
    --topology incast \
    --schemes REACTIVE PERIODIC_16 PERIODIC_32 PTT \
    --microburst \
    --bottleneck-rate-pps "$BOTTLENECK_RATE" \
    "$@"

echo ""
echo "Microburst experiment complete."
