#!/usr/bin/env bash
# Validate that all required tools and dependencies are available.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass_count=0
fail_count=0
warn_count=0

check_cmd() {
    local name="$1"
    local cmd="${2:-$1}"
    if command -v "$cmd" &>/dev/null; then
        echo -e "  ${GREEN}[PASS]${NC} $name ($(command -v "$cmd"))"
        ((pass_count++))
    else
        echo -e "  ${RED}[FAIL]${NC} $name not found"
        ((fail_count++))
    fi
}

check_python_pkg() {
    local pkg="$1"
    if python3 -c "import $pkg" 2>/dev/null; then
        echo -e "  ${GREEN}[PASS]${NC} Python: $pkg"
        ((pass_count++))
    else
        echo -e "  ${RED}[FAIL]${NC} Python: $pkg not importable"
        ((fail_count++))
    fi
}

check_cmd_optional() {
    local name="$1"
    local cmd="${2:-$1}"
    if command -v "$cmd" &>/dev/null; then
        echo -e "  ${GREEN}[PASS]${NC} $name ($(command -v "$cmd"))"
        ((pass_count++))
    else
        echo -e "  ${YELLOW}[WARN]${NC} $name not found (optional)"
        ((warn_count++))
    fi
}

echo "=== PTT-INT Environment Validation ==="
echo ""

# --- Required binaries ---
echo "Required binaries:"
check_cmd "p4c-bm2-ss"
check_cmd "simple_switch"
check_cmd "simple_switch_CLI"
check_cmd "python3"
check_cmd "tcpdump"
echo ""

# --- Python packages ---
echo "Python packages:"
check_python_pkg "scapy"
check_python_pkg "yaml"
check_python_pkg "numpy"
check_python_pkg "matplotlib"
echo ""

# --- Versions ---
echo "Versions:"
if command -v simple_switch &>/dev/null; then
    echo "  simple_switch: $(simple_switch --version 2>&1 | head -1 || echo 'unknown')"
fi
if command -v p4c-bm2-ss &>/dev/null; then
    echo "  p4c-bm2-ss: $(p4c-bm2-ss --version 2>&1 | head -1 || echo 'unknown')"
fi
echo "  python3: $(python3 --version)"
echo "  kernel: $(uname -r)"
echo ""

# --- sudo check ---
echo "Permissions:"
if sudo -n true 2>/dev/null; then
    echo -e "  ${GREEN}[PASS]${NC} sudo available (passwordless)"
    ((pass_count++))
else
    echo -e "  ${YELLOW}[WARN]${NC} sudo requires password — experiments need root"
    ((warn_count++))
fi
echo ""

# --- P4 compilation ---
echo "P4 compilation check:"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -f "$REPO_ROOT/p4src/ptt_int.json" ]; then
    echo -e "  ${GREEN}[PASS]${NC} ptt_int.json exists"
    ((pass_count++))
else
    echo -e "  ${RED}[FAIL]${NC} ptt_int.json missing — run: p4c-bm2-ss --std p4-16 -o p4src/ptt_int.json p4src/ptt_int.p4"
    ((fail_count++))
fi

# Verify P4 compiles cleanly
TMP_JSON=$(mktemp /tmp/ptt_validate_XXXXXX.json)
if p4c-bm2-ss --std p4-16 -o "$TMP_JSON" "$REPO_ROOT/p4src/ptt_int.p4" 2>/dev/null; then
    echo -e "  ${GREEN}[PASS]${NC} P4 compiles without errors"
    ((pass_count++))
    rm -f "$TMP_JSON"
else
    echo -e "  ${RED}[FAIL]${NC} P4 compilation failed"
    ((fail_count++))
fi
echo ""

# --- Summary ---
echo "========================================="
echo -e "Results: ${GREEN}$pass_count passed${NC}, ${RED}$fail_count failed${NC}, ${YELLOW}$warn_count warnings${NC}"
echo "========================================="

if [ "$fail_count" -gt 0 ]; then
    echo "Some required dependencies are missing. Install them before proceeding."
    exit 1
else
    echo "Environment is ready for PTT-INT experiments."
    exit 0
fi
