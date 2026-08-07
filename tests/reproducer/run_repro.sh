#!/usr/bin/env bash
# ===========================================================================
# Isolated BMv2 Queue-Metadata Reproducer — Run Script
#
# Run this with sudo:
#   sudo bash tests/reproducer/run_repro.sh
# ===========================================================================
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
RESULT_DIR="${REPO}/results/reproducer_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULT_DIR"

echo "=== BMv2 Queue-Metadata Reproducer ===" | tee "$RESULT_DIR/report.txt"
echo "Date: $(date)" | tee -a "$RESULT_DIR/report.txt"
echo "" | tee -a "$RESULT_DIR/report.txt"

# ---------- Version Info ----------
echo "--- BMv2 & p4c Versions ---" | tee -a "$RESULT_DIR/report.txt"
echo "which simple_switch: $(which simple_switch)" | tee -a "$RESULT_DIR/report.txt"
echo "simple_switch --version: $(simple_switch --version 2>&1)" | tee -a "$RESULT_DIR/report.txt"
echo "which simple_switch_CLI: $(which simple_switch_CLI)" | tee -a "$RESULT_DIR/report.txt"
echo "p4c --version: $(p4c --version 2>&1)" | tee -a "$RESULT_DIR/report.txt"
echo "" | tee -a "$RESULT_DIR/report.txt"

# ---------- BMv2 Source Info ----------
BMV2_SRC="/home/howard/behavioral-model"
if [ -d "$BMV2_SRC" ]; then
    echo "--- BMv2 Source Tree ---" | tee -a "$RESULT_DIR/report.txt"
    echo "Path: $BMV2_SRC" | tee -a "$RESULT_DIR/report.txt"
    echo "Git commit: $(git -C "$BMV2_SRC" log -1 --format='%H %s')" | tee -a "$RESULT_DIR/report.txt"
    echo "" | tee -a "$RESULT_DIR/report.txt"

    echo "--- enq_qdepth / deq_qdepth Assignments ---" | tee -a "$RESULT_DIR/report.txt"
    echo "" | tee -a "$RESULT_DIR/report.txt"
    echo "==> simple_switch.cpp (enqueue, ~line 418-419):" | tee -a "$RESULT_DIR/report.txt"
    grep -n "enq_qdepth" "$BMV2_SRC/targets/simple_switch/simple_switch.cpp" | tee -a "$RESULT_DIR/report.txt" || true
    echo "" | tee -a "$RESULT_DIR/report.txt"
    echo "==> simple_switch.cpp (dequeue, ~line 670-671):" | tee -a "$RESULT_DIR/report.txt"
    grep -n "deq_qdepth" "$BMV2_SRC/targets/simple_switch/simple_switch.cpp" | tee -a "$RESULT_DIR/report.txt" || true
    echo "" | tee -a "$RESULT_DIR/report.txt"
    echo "==> Relevant Source Lines:" | tee -a "$RESULT_DIR/report.txt"
    sed -n '410,425p' "$BMV2_SRC/targets/simple_switch/simple_switch.cpp" | tee -a "$RESULT_DIR/report.txt"
    echo "..." | tee -a "$RESULT_DIR/report.txt"
    sed -n '645,680p' "$BMV2_SRC/targets/simple_switch/simple_switch.cpp" | tee -a "$RESULT_DIR/report.txt"
    echo "" | tee -a "$RESULT_DIR/report.txt"
    echo "==> QueueingLogicPriRL::size(queue_id, priority) from queueing.h:" | tee -a "$RESULT_DIR/report.txt"
    sed -n '619,635p' "$BMV2_SRC/include/bm/bm_sim/queueing.h" | tee -a "$RESULT_DIR/report.txt"
    echo "" | tee -a "$RESULT_DIR/report.txt"
    echo "==> egress_buffers type declaration (simple_switch.h):" | tee -a "$RESULT_DIR/report.txt"
    grep -n "egress_buffers" "$BMV2_SRC/targets/simple_switch/simple_switch.h" | tee -a "$RESULT_DIR/report.txt" || true
else
    echo "BMv2 source not found at $BMV2_SRC" | tee -a "$RESULT_DIR/report.txt"
fi

echo "" | tee -a "$RESULT_DIR/report.txt"

# ---------- Compile P4 (if needed) ----------
P4_JSON="$REPO/tests/reproducer/queue_repro.json"
P4_SRC="$REPO/tests/reproducer/queue_repro.p4"

if [ ! -f "$P4_JSON" ] || [ "$P4_SRC" -nt "$P4_JSON" ]; then
    echo "--- Compiling P4 Program ---" | tee -a "$RESULT_DIR/report.txt"
    p4c-bm2-ss --p4v 16 -o "$P4_JSON" "$P4_SRC" 2>&1 | tee -a "$RESULT_DIR/report.txt"
    echo "Compilation done." | tee -a "$RESULT_DIR/report.txt"
fi

# ---------- Run Python Test ----------
echo "" | tee -a "$RESULT_DIR/report.txt"
echo "--- Running Reproducer ---" | tee -a "$RESULT_DIR/report.txt"
python3 "$REPO/tests/reproducer/run_queue_repro.py" 2>&1 | tee -a "$RESULT_DIR/report.txt"

echo "" | tee -a "$RESULT_DIR/report.txt"
echo "=== Report saved to: $RESULT_DIR/report.txt ==="
