#!/usr/bin/env bash
# Sensitivity/Ablation experiment (E3 subset).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== PTT-INT Sensitivity & Ablation Experiment ==="
echo ""

BOTTLENECK_RATE="${BOTTLENECK_RATE:-100}"

sudo python3 experiments/run_matrix.py \
    --experiment sensitivity \
    --topology single_bottleneck \
    --sensitivity \
    --bottleneck-rate-pps "$BOTTLENECK_RATE" \
    "$@"

echo ""
echo "Sensitivity/Ablation experiment complete."
