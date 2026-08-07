#!/usr/bin/env bash
# PTT-INT: Build script
# Compiles the P4 program and generates P4 parameters from config.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== PTT-INT Build ==="

# Step 1: Generate P4 parameters from YAML config
echo "[1/2] Generating P4 parameters..."
python3 "$REPO_ROOT/control/generate_p4_params.py"

# Step 2: Compile P4 program
echo "[2/2] Compiling P4 program..."
cd "$REPO_ROOT/p4src"

# Compile the monolithic self-contained program
p4c-bm2-ss --std p4-16 -o ptt_int.json ptt_int.p4

echo "=== Build complete ==="
echo "Output: $REPO_ROOT/p4src/ptt_int.json"
