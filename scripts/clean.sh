#!/usr/bin/env bash
# PTT-INT: Clean build artifacts and results
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Cleaning PTT-INT..."

# Remove compiled P4
rm -f "$REPO_ROOT/p4src/ptt_int.json"

# Remove generated P4 params
rm -f "$REPO_ROOT/p4src/generated_params.p4"

# Clean results (use with caution!)
if [ "${1:-}" = "--all" ]; then
    echo "Removing all results..."
    rm -rf "$REPO_ROOT/results/raw/"*
    rm -rf "$REPO_ROOT/results/processed/"*
    rm -rf "$REPO_ROOT/results/figures/"*
    rm -rf "$REPO_ROOT/results/tables/"*
fi

# Remove Python cache
find "$REPO_ROOT" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find "$REPO_ROOT" -type f -name "*.pyc" -delete 2>/dev/null || true

echo "Clean complete."
echo "Use 'bash scripts/clean.sh --all' to also remove results."
