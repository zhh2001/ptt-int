#!/usr/bin/env bash
# Gate A: Queue Calibration
# Proves real BMv2 queue buildup at different offered loads.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== Gate A: Queue Calibration ==="
echo ""

# Default bottleneck rate (packets per second)
QUEUE_RATE="${QUEUE_RATE:-100}"
OUTPUT_DIR="${OUTPUT_DIR:-results/raw/queue_calibration}"

echo "Bottleneck service rate: $QUEUE_RATE pps"
echo "Output directory: $OUTPUT_DIR"
echo ""

sudo python3 experiments/queue_calibration.py \
    --queue-rate-pps "$QUEUE_RATE" \
    --output-dir "$OUTPUT_DIR" \
    --duration 12 \
    --warmup 2 \
    "$@"

echo ""
echo "Gate A complete."
echo "Check $OUTPUT_DIR/queue_calibration.png and $OUTPUT_DIR/queue_calibration.csv"
