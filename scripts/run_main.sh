#!/usr/bin/env bash
# Main experiment matrix (RQ-driven: E1 → E2 → E3 → E4).
# Run AFTER Gates A/B/C pass and Pilot go/no-go is confirmed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== PTT-INT Main Experiment Matrix ==="
echo ""

BOTTLENECK_RATE="${BOTTLENECK_RATE:-100}"
SEEDS="${SEEDS:-101..120}"

echo "E1: Single bottleneck comparison"
echo "  7 schemes × 8 workloads × 20 seeds = 1120 runs"
sudo python3 experiments/run_matrix.py \
    --experiment e1_single_bottleneck \
    --topology single_bottleneck \
    --schemes FULL PERIODIC_4 PERIODIC_16 PERIODIC_32 REACTIVE DELTA PTT \
    --workloads stable_60 stable_80 ramp_slow ramp_medium ramp_fast step periodic_burst mixed \
    --bottleneck-rate-pps "$BOTTLENECK_RATE" \
    "$@"

echo "E2: Incast + Microburst"
echo "  4 schemes × 12 microburst configs × 20 seeds = 960 runs"
sudo python3 experiments/run_matrix.py \
    --experiment e2_incast_microburst \
    --topology incast \
    --schemes REACTIVE PERIODIC_16 PERIODIC_32 PTT \
    --microburst \
    --bottleneck-rate-pps "$BOTTLENECK_RATE" \
    "$@"

echo "E3: Sensitivity + Ablation"
echo "  ~170 runs"
sudo python3 experiments/run_matrix.py \
    --experiment e3_sensitivity \
    --topology single_bottleneck \
    --sensitivity \
    --bottleneck-rate-pps "$BOTTLENECK_RATE" \
    "$@"

echo "E4: Leaf-spine scalability"
echo "  3 schemes × 3 workloads × 15 seeds = 135 runs"
sudo python3 experiments/run_matrix.py \
    --experiment e4_leaf_spine \
    --topology leaf_spine \
    --schemes REACTIVE PTT FULL \
    --workloads stable_80 ramp_medium mixed \
    --bottleneck-rate-pps "$BOTTLENECK_RATE" \
    "$@"

echo ""
echo "Main matrix complete."
