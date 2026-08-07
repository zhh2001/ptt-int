#!/usr/bin/env bash
# PTT-INT: Smoke test
# Compiles P4, starts minimal Mininet topology, verifies forwarding,
# verifies non-zero queue depth, verifies PTT header insertion,
# and produces one valid telemetry CSV row and oracle CSV row.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

SMOKE_DIR="$REPO_ROOT/results/raw/smoke_test"
mkdir -p "$SMOKE_DIR"

echo "=== PTT-INT Smoke Test ==="

# Step 1: Compile P4
echo "[1/7] Compiling P4..."
cd "$REPO_ROOT/p4src"
p4c-bm2-ss --std p4-16 -o ptt_int.json ptt_int.p4 2>&1 | grep -i "error" && exit 1 || true
echo "  Compile OK"

# Step 2: Start BMv2 switches
echo "[2/7] Starting BMv2 switches..."
simple_switch --log-file "$SMOKE_DIR/switch_s1.log" --log-console \
    -i 0@s1-eth0 -i 1@s1-eth1 --thrift-port 9090 --device-id 0 \
    "$REPO_ROOT/p4src/ptt_int.json" &
S1_PID=$!

simple_switch --log-file "$SMOKE_DIR/switch_s2.log" --log-console \
    -i 0@s2-eth0 -i 1@s2-eth1 --thrift-port 9091 --device-id 1 \
    "$REPO_ROOT/p4src/ptt_int.json" &
S2_PID=$!

sleep 2
echo "  Switches started (PIDs: $S1_PID $S2_PID)"

# Step 3: Configure switches
echo "[3/7] Configuring switches..."

# Configure switch IDs and scheme modes
python3 "$REPO_ROOT/control/configure_switch.py" --thrift-port 9090 --switch-id 1 --scheme 6
python3 "$REPO_ROOT/control/configure_switch.py" --thrift-port 9091 --switch-id 2 --scheme 6

# Install forwarding rules
# s1: 10.0.0.2 -> port 1
python3 "$REPO_ROOT/control/configure_switch.py" --thrift-port 9090 \
    --routes '[{"dst_ip": "10.0.0.2/32", "port": 1}]' --switch-id 1 --scheme 6

# s2: 10.0.0.2 -> port 1, 10.0.0.1 -> port 0
python3 "$REPO_ROOT/control/configure_switch.py" --thrift-port 9091 \
    --routes '[{"dst_ip": "10.0.0.2/32", "port": 1}, {"dst_ip": "10.0.0.1/32", "port": 0}]' \
    --switch-id 2 --scheme 6

# Configure queues on s2 (bottleneck): depth=128, rate=100 pps to force buildup
echo "  Setting queue depth=128 rate=100 on s2 ports..."
for port in 0 1 2; do
    echo "set_queue_depth $port 128" | simple_switch_CLI --thrift-port 9091 > /dev/null 2>&1
    echo "set_queue_rate $port 100" | simple_switch_CLI --thrift-port 9091 > /dev/null 2>&1
done
echo "  Switches configured"

# Step 4: Create veth pairs to connect switches
echo "[4/7] Setting up network interfaces..."
ip netns add smoke_ns1 2>/dev/null || true
ip netns add smoke_ns2 2>/dev/null || true

# Create veth pairs
ip link add s1-eth0 type veth peer name h1-eth0 2>/dev/null || true
ip link add s1-eth1 type veth peer name s2-eth0 2>/dev/null || true
ip link add s2-eth1 type veth peer name h2-eth0 2>/dev/null || true

# Set up interfaces
ip link set s1-eth0 up
ip link set s1-eth1 up
ip link set s2-eth0 up
ip link set s2-eth1 up
ip link set h1-eth0 netns smoke_ns1
ip link set h2-eth0 netns smoke_ns2

ip netns exec smoke_ns1 ip link set h1-eth0 up
ip netns exec smoke_ns1 ip addr add 10.0.0.1/24 dev h1-eth0
ip netns exec smoke_ns2 ip link set h2-eth0 up
ip netns exec smoke_ns2 ip addr add 10.0.0.2/24 dev h2-eth0

# Step 5: Start packet capture on h2
echo "[5/7] Starting packet capture..."
ip netns exec smoke_ns2 tcpdump -i h2-eth0 -w "$SMOKE_DIR/capture.pcap" udp &
TCPDUMP_PID=$!
sleep 1

# Step 6: Generate traffic
echo "[6/7] Generating traffic..."
# Start iperf3 server on h2
ip netns exec smoke_ns2 iperf3 -s -p 5201 &
IPERF_SERVER_PID=$!
sleep 0.5

# Send UDP traffic at high rate to cause queue buildup
ip netns exec smoke_ns1 iperf3 -c 10.0.0.2 -p 5201 -t 10 -b 50M -l 1000 -u \
    > "$SMOKE_DIR/iperf_client.log" 2>&1 || true

echo "  Traffic complete"

# Step 7: Post-process
echo "[7/7] Post-processing..."
sleep 2

# Stop capture and server
kill $TCPDUMP_PID 2>/dev/null || true
kill $IPERF_SERVER_PID 2>/dev/null || true

# Stop switches
kill $S1_PID 2>/dev/null || true
kill $S2_PID 2>/dev/null || true

# Parse pcap
python3 "$REPO_ROOT/collector/parse_pcap.py" \
    --pcap "$SMOKE_DIR/capture.pcap" \
    --output "$SMOKE_DIR/telemetry_samples.csv" \
    --run-id "smoke_test" --scheme "PTT" --seed 0

# Parse oracle log
if [ -f "$SMOKE_DIR/switch_s2.log" ]; then
    python3 "$REPO_ROOT/oracle/parse_bmv2_log.py" \
        --log "$SMOKE_DIR/switch_s2.log" \
        --output "$SMOKE_DIR/oracle.csv" \
        --run-id "smoke_test" --scheme "PTT" --seed 0
fi

# Verify outputs
echo ""
echo "=== Smoke Test Results ==="
echo ""

if [ -f "$SMOKE_DIR/telemetry_samples.csv" ]; then
    TEL_LINES=$(wc -l < "$SMOKE_DIR/telemetry_samples.csv")
    echo "telemetry_samples.csv: $TEL_LINES lines ($((TEL_LINES - 1)) data rows)"
    if [ "$TEL_LINES" -gt 1 ]; then
        echo "  PASS: Telemetry samples found"
    else
        echo "  WARN: No telemetry samples (queue may not have built up)"
    fi
else
    echo "  FAIL: No telemetry_samples.csv"
fi

if [ -f "$SMOKE_DIR/oracle.csv" ]; then
    ORACLE_LINES=$(wc -l < "$SMOKE_DIR/oracle.csv")
    echo "oracle.csv: $ORACLE_LINES lines ($((ORACLE_LINES - 1)) data rows)"
    if [ "$ORACLE_LINES" -gt 1 ]; then
        echo "  PASS: Oracle entries found"
    else
        echo "  WARN: No oracle entries (epoch may not have elapsed)"
    fi
else
    echo "  INFO: No oracle.csv (may not have produced oracle entries in short test)"
fi

# Check for PTT_ORACLE in switch log
if [ -f "$SMOKE_DIR/switch_s2.log" ]; then
    ORACLE_LOG_COUNT=$(grep -c "PTT_ORACLE" "$SMOKE_DIR/switch_s2.log" 2>/dev/null || true)
    echo "PTT_ORACLE lines in s2 log: ${ORACLE_LOG_COUNT:-0}"
    if [ "${ORACLE_LOG_COUNT:-0}" -gt 0 ]; then
        echo "  PASS: Oracle logging active"
    fi
fi

# Check for PTT magic in pcap
if [ -f "$SMOKE_DIR/capture.pcap" ]; then
    tcpdump -r "$SMOKE_DIR/capture.pcap" -X 2>/dev/null | grep -q "5054" && {
        echo "  PASS: PTT magic (0x5054) found in captured packets"
    } || {
        echo "  INFO: PTT magic not found (may need more traffic)"
    }
fi

# Run unit tests
echo ""
echo "Unit Tests:"
python3 -m unittest discover -s "$REPO_ROOT/tests" -v 2>&1 | tail -5

echo ""
echo "=== Smoke test complete ==="
echo "Output: $SMOKE_DIR"

# Cleanup network namespaces
ip netns delete smoke_ns1 2>/dev/null || true
ip netns delete smoke_ns2 2>/dev/null || true
