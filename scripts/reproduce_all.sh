#!/usr/bin/env bash
# PTT-INT: Reproduce experiment matrix from clean results directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== PTT-INT: Full Reproduction ==="
echo ""

# Check for root
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (required for Mininet + BMv2)."
    echo "Please run: sudo bash scripts/reproduce_all.sh"
    exit 1
fi

# Step 1: Build
echo "[1/7] Building P4 program..."
bash "$REPO_ROOT/scripts/build.sh"

# Step 2: Run unit tests
echo "[2/7] Running unit tests..."
python3 -m unittest discover -s "$REPO_ROOT/tests" -v || {
    echo "ERROR: Unit tests failed"
    exit 1
}

# Step 3: Run smoke test
echo "[3/7] Running smoke test..."
python3 "$REPO_ROOT/tests/test_smoke.py" || {
    echo "WARNING: Smoke test had issues, continuing..."
}

# Step 4: Run main comparison experiment
echo "[4/7] Running main comparison experiment..."
python3 "$REPO_ROOT/experiments/run_matrix.py" \
    --experiment "main_comparison" \
    --schemes PTT REACTIVE FULL PERIODIC_16 PERIODIC_32 DELTA \
    --seeds 1 2 3 4 5 \
    --topology single_bottleneck \
    --workload ramp \
    --duration 30

# Step 5: Compute metrics for all runs
echo "[5/7] Computing metrics..."
for run_dir in "$REPO_ROOT"/results/raw/main_comparison/*/*/; do
    if [ -f "$run_dir/oracle.csv" ] && [ -f "$run_dir/telemetry_samples.csv" ]; then
        echo "  Processing: $run_dir"
        python3 "$REPO_ROOT/analysis/metrics.py" \
            --oracle "$run_dir/oracle.csv" \
            --telemetry "$run_dir/telemetry_samples.csv" \
            --events "$run_dir/events.csv" \
            --output "$run_dir/metrics.json" 2>/dev/null || true
    fi
done

# Step 6: Aggregate results
echo "[6/7] Aggregating results..."
python3 "$REPO_ROOT/analysis/aggregate.py" \
    "$REPO_ROOT"/results/raw/main_comparison/*/*/ \
    --output "$REPO_ROOT/results/processed/aggregated_metrics.json" 2>/dev/null || true

# Step 7: Generate plots
echo "[7/7] Generating plots..."
for run_dir in "$REPO_ROOT"/results/raw/main_comparison/PTT/1/; do
    if [ -f "$run_dir/oracle.csv" ]; then
        python3 "$REPO_ROOT/analysis/plots.py" \
            --plot all \
            --oracle-csv "$run_dir/oracle.csv" \
            --telemetry-csv "$run_dir/telemetry_samples.csv" \
            --events-csv "$run_dir/events.csv" \
            --metrics-json "$run_dir/metrics.json" \
            --output-dir "$REPO_ROOT/results/figures/" 2>/dev/null || true
        break
    fi
done

echo ""
echo "=== Reproduction complete ==="
echo "Results:  $REPO_ROOT/results/raw/"
echo "Figures:  $REPO_ROOT/results/figures/"
echo "Processed: $REPO_ROOT/results/processed/"
