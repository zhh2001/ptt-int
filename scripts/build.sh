#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="$(realpath "${1:-$REPO_ROOT/config/default.yaml}")"
OUTPUT="$(realpath -m "${2:-$REPO_ROOT/build}")"
mkdir -p "$OUTPUT"
python3 "$REPO_ROOT/control/generate_p4_params.py" --config "$CONFIG" --output "$OUTPUT/generated_params.p4"
# Replace the artifact only after a successful compilation.
p4c-bm2-ss --std p4-16 -I "$OUTPUT" -o "$OUTPUT/ptt_int.json.tmp" "$REPO_ROOT/p4src/ptt_int.p4"
mv "$OUTPUT/ptt_int.json.tmp" "$OUTPUT/ptt_int.json"
echo "Built $OUTPUT/ptt_int.json"
