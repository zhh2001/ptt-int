#!/usr/bin/env bash
# Pilot experiment: PTT vs REACTIVE on ramp workloads, seeds 1-5.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== PTT-INT Pilot Experiment ==="
echo "Schemes: PTT, REACTIVE"
echo "Workloads: ramp_slow, ramp_medium, ramp_fast"
echo "Seeds: 1-5"
echo "Topology: single_bottleneck"
echo "Total runs: 30"
echo ""

BOTTLENECK_RATE="${BOTTLENECK_RATE:-100}"
OUTPUT_DIR="${OUTPUT_DIR:-results/raw/pilot}"

sudo python3 experiments/run_pilot.py \
    --bottleneck-rate-pps "$BOTTLENECK_RATE" \
    --output-dir "$OUTPUT_DIR" \
    "$@"

echo ""
echo "Pilot complete."
echo "Check $OUTPUT_DIR/pilot_results.json and $OUTPUT_DIR/pilot_go_nogo.md"
