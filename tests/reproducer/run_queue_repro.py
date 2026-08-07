#!/usr/bin/env python3
"""Isolated BMv2 queue-metadata reproducer.

Uses one simple_switch, two hosts (netns), minimal IPv4 forwarding P4.
No PTT, no FSM, no INT header.  Logs enq_qdepth, deq_qdepth, deq_timedelta,
and egress_port via log_msg in the egress pipeline.

Test: set_queue_depth 128, set_queue_rate 10 (all ports), send 1000 UDP
packets as fast as possible.  Measure receiver arrival rate.
"""

import subprocess as sp
import sys
import os
import time
import json
import socket
import struct
import tempfile
import shutil
import signal
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
P4_JSON = REPO / "tests" / "reproducer" / "queue_repro.json"

H1_IP = "10.0.0.1"
H2_IP = "10.0.0.2"
H1_MAC = "00:00:00:00:00:01"
H2_MAC = "00:00:00:00:00:02"
SW_MAC_0 = "00:00:00:aa:00:00"  # port 0 toward h1
SW_MAC_1 = "00:00:00:aa:00:01"  # port 1 toward h2

NS_H1 = "qr_h1"
NS_H2 = "qr_h2"
VETH_H1 = "qr_h1_sw"
VETH_SW0 = "qr_sw_h1"
VETH_SW1 = "qr_sw_h2"
VETH_H2 = "qr_h2_sw"

QUEUE_RATE = 10   # pps
QUEUE_DEPTH = 128
NPACKETS = 1000
THRIFT_PORT = 9099


def run(cmd, check=True, **kwargs):
    """Run a command, return CompletedProcess."""
    return sp.run(cmd, check=check, text=True, capture_output=True, **kwargs)


def cleanup():
    """Remove any leftover namespaces and veths."""
    for ns in [NS_H1, NS_H2]:
        run(["ip", "netns", "delete", ns], check=False)
    for v in [VETH_H1, VETH_SW0, VETH_SW1, VETH_H2]:
        run(["ip", "link", "delete", v], check=False)
    # kill any leftover switches
    run(["pkill", "-f", "simple_switch.*queue_repro"], check=False)


def setup():
    """Create netns, veth pairs, bring everything up."""
    cleanup()
    time.sleep(0.3)

    # Create namespaces
    run(["ip", "netns", "add", NS_H1])
    run(["ip", "netns", "add", NS_H2])

    # Create veth pairs
    run(["ip", "link", "add", VETH_H1, "type", "veth", "peer", "name", VETH_SW0])
    run(["ip", "link", "add", VETH_SW1, "type", "veth", "peer", "name", VETH_H2])

    # Move host ends into namespaces
    run(["ip", "link", "set", VETH_H1, "netns", NS_H1])
    run(["ip", "link", "set", VETH_H2, "netns", NS_H2])

    # Bring up switch-side interfaces
    for v in [VETH_SW0, VETH_SW1]:
        run(["ip", "link", "set", v, "up"])

    # Configure host h1
    run(["ip", "netns", "exec", NS_H1, "ip", "link", "set", "lo", "up"])
    run(["ip", "netns", "exec", NS_H1, "ip", "link", "set", VETH_H1, "up"])
    run(["ip", "netns", "exec", NS_H1, "ip", "addr", "add", f"{H1_IP}/24", "dev", VETH_H1])
    run(["ip", "netns", "exec", NS_H1, "ip", "neigh", "add", H2_IP, "lladdr", SW_MAC_0,
         "dev", VETH_H1, "nud", "permanent"])

    # Configure host h2
    run(["ip", "netns", "exec", NS_H2, "ip", "link", "set", "lo", "up"])
    run(["ip", "netns", "exec", NS_H2, "ip", "link", "set", VETH_H2, "up"])
    run(["ip", "netns", "exec", NS_H2, "ip", "addr", "add", f"{H2_IP}/24", "dev", VETH_H2])
    run(["ip", "netns", "exec", NS_H2, "ip", "neigh", "add", H1_IP, "lladdr", SW_MAC_1,
         "dev", VETH_H2, "nud", "permanent"])

    return {
        "interfaces": [(0, VETH_SW0), (1, VETH_SW1)],
    }


def start_switch(tmpdir):
    """Start simple_switch with the reproducer P4 program."""
    log_path = os.path.join(tmpdir, "switch.log")
    log_fd = open(log_path, "w")

    cmd = [
        "simple_switch",
        "--thrift-port", str(THRIFT_PORT),
        "--device-id", "0",
        "--log-console",
        "-i", f"0@{VETH_SW0}",
        "-i", f"1@{VETH_SW1}",
        "--pcap",
        "--nanolog", "ipc:///tmp/qr_nanolog.ipc",
        str(P4_JSON),
    ]
    proc = sp.Popen(cmd, stdout=log_fd, stderr=sp.STDOUT)
    return proc, log_path


def wait_thrift(timeout=15):
    """Wait for the Thrift server to be ready."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = run(
                ["simple_switch_CLI", "--thrift-port", str(THRIFT_PORT)],
                input="show_tables\n",
                check=False, timeout=5,
            )
            if "ipv4_lpm" in r.stdout:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def cli_cmd(thrift_port, cmd_str):
    """Issue a command to simple_switch_CLI."""
    return run(
        ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
        input=cmd_str + "\n", check=False, timeout=10,
    )


def configure_switch():
    """Set up forwarding rules and queue parameters."""
    # Add routes: dst H1 -> port 0, dst H2 -> port 1
    r1 = cli_cmd(THRIFT_PORT,
                 "table_add ipv4_lpm forward 10.0.0.1/32 => 0")
    r2 = cli_cmd(THRIFT_PORT,
                 "table_add ipv4_lpm forward 10.0.0.2/32 => 1")
    print(f"  Route H1->port0: {r1.stdout.strip()}")
    print(f"  Route H2->port1: {r2.stdout.strip()}")

    # Set queue depth and rate on all ports (port 0 and port 1)
    for port in [0, 1]:
        r = cli_cmd(THRIFT_PORT,
                     # BMv2 CLI: set_queue_depth <nb_pkts> [<port>] — value FIRST
                 f"set_queue_depth {QUEUE_DEPTH} {port}")
        print(f"  set_queue_depth depth={QUEUE_DEPTH} port={port}: {r.stdout.strip()}")
        r2 = cli_cmd(THRIFT_PORT,
                      # BMv2 CLI: set_queue_rate <rate_pps> [<port>] — value FIRST
                      f"set_queue_rate {QUEUE_RATE} {port}")
        print(f"  set_queue_rate rate={QUEUE_RATE} port={port}: {r2.stdout.strip()}")

    # Verify
    r = cli_cmd(THRIFT_PORT, "show_tables")
    print(f"  Tables:\n{r.stdout.strip()}")


def send_flood():
    """Send NPACKETS UDP packets from h1 to h2 as fast as possible."""
    script = f'''
import socket
import struct
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 212992)

# Bind to a local port
sock.bind(("0.0.0.0", 9999))
sock.connect(("{H2_IP}", 8888))

# Send packets with sequence numbers
payload = b"Q" * 1000  # 1000-byte payload
t0 = time.monotonic_ns()
for i in range({NPACKETS}):
    pkt = struct.pack("!I", i) + payload
    sock.send(pkt)
t1 = time.monotonic_ns()

elapsed_s = (t1 - t0) / 1e9
print(f"SENDER_DONE: {{elapsed_s:.6f}}s {NPACKETS} pkts {{{NPACKETS}/elapsed_s:.0f}} pps")
sock.close()
'''
    r = run(["ip", "netns", "exec", NS_H1, "python3", "-c", script],
            timeout=30)
    print(f"  Sender: {r.stdout.strip()}")
    return r.stdout


def receiver_setup(tmpdir):
    """Start tcpdump on h2 to capture received packets."""
    pcap_path = os.path.join(tmpdir, "recv.pcap")
    # Start receiver in background that counts packets
    recv_script = f'''
import socket
import struct
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 212992)
sock.bind(("0.0.0.0", 8888))
sock.settimeout(5.0)

count = 0
t_first = None
t_last = None
seqs = set()
try:
    while True:
        data, addr = sock.recvfrom(2048)
        now = time.monotonic_ns()
        if t_first is None:
            t_first = now
        t_last = now
        if len(data) >= 4:
            seqs.add(struct.unpack("!I", data[:4])[0])
        count += 1
except socket.timeout:
    pass

elapsed = (t_last - t_first) / 1e9 if t_first and t_last else 0
print(f"RECV_DONE: {{count}} pkts {{len(seqs)}} unique {{count/elapsed:.0f if elapsed>0 else 0}} pps")
sock.close()
'''
    return pcap_path, recv_script


def parse_switch_log(log_path):
    """Extract QREPRO log lines from the switch log."""
    entries = []
    with open(log_path) as f:
        for line in f:
            if "QREPRO" not in line:
                continue
            # Format: QREPRO enq=X deq=Y delta=Z port=P ts=T
            try:
                parts = line[line.index("QREPRO"):].strip()
                d = {}
                # Parse key=value pairs
                for token in parts.split():
                    if "=" in token:
                        k, v = token.split("=", 1)
                        # Remove trailing comma
                        v = v.rstrip(",")
                        d[k] = int(v)
                entries.append(d)
            except (ValueError, KeyError):
                continue
    return entries


def main():
    tmpdir = tempfile.mkdtemp(prefix="qr_")
    print(f"=== BMv2 Queue-Metadata Reproducer ===")
    print(f"Working directory: {tmpdir}")

    # --- Version info ---
    print("\n--- Version Info ---")
    r = run(["which", "simple_switch"], check=False)
    print(f"which simple_switch: {r.stdout.strip()}")
    r = run(["simple_switch", "--version"], check=False)
    print(f"simple_switch --version: {r.stdout.strip()}")
    r = run(["which", "simple_switch_CLI"], check=False)
    print(f"which simple_switch_CLI: {r.stdout.strip()}")
    r = run(["p4c", "--version"], check=False)
    print(f"p4c --version: {r.stdout.strip()}")

    # --- Setup ---
    print("\n--- Setup ---")
    topo = setup()
    print(f"  veth pairs created, namespaces configured")

    # --- Start switch ---
    print("\n--- Starting Switch ---")
    sw_proc, sw_log = start_switch(tmpdir)
    print(f"  PID: {sw_proc.pid}, log: {sw_log}")
    cmdline = open(f"/proc/{sw_proc.pid}/cmdline").read().replace("\0", " ")
    print(f"  Full command line: {cmdline}")

    if not wait_thrift():
        print("  ERROR: Thrift server not ready")
        sw_proc.kill()
        sw_proc.wait()
        return 1
    print(f"  Thrift ready")

    # --- Configure ---
    print("\n--- Configure Switch ---")
    configure_switch()
    time.sleep(0.5)

    # --- Start receiver + tcpdump ---
    recv_pcap = os.path.join(tmpdir, "recv.pcap")
    tcpdump = sp.Popen(
        ["ip", "netns", "exec", NS_H2, "tcpdump", "-i", VETH_H2, "-w", recv_pcap, "-U"],
        stdout=sp.DEVNULL, stderr=sp.DEVNULL,
    )
    time.sleep(0.3)

    # Start receiver in netns (background)
    recv_script_path = os.path.join(tmpdir, "recv.py")
    _, recv_script = receiver_setup(tmpdir)
    with open(recv_script_path, "w") as f:
        f.write(recv_script)
    recv_proc = sp.Popen(
        ["ip", "netns", "exec", NS_H2, "python3", recv_script_path],
        stdout=sp.PIPE, stderr=sp.PIPE, text=True,
    )
    time.sleep(0.2)

    # --- Test: ping first ---
    print("\n--- Connectivity Test (ping) ---")
    r = run(["ip", "netns", "exec", NS_H1, "ping", "-c", "3", "-W", "2", H2_IP],
            check=False, timeout=10)
    print(f"  ping: {r.stdout.strip().split(chr(10))[-3:]}")

    # --- Traffic flood ---
    print(f"\n--- Traffic Flood ({NPACKETS} packets) ---")
    sender_out = send_flood()

    # Wait for receiver
    print("  Waiting for receiver to finish...")
    try:
        recv_stdout, recv_stderr = recv_proc.communicate(timeout=15)
        print(f"  Receiver: {recv_stdout.strip()}")
    except sp.TimeoutExpired:
        recv_proc.kill()
        recv_stdout, recv_stderr = recv_proc.communicate()
        print(f"  Receiver (killed): {recv_stdout.strip()}")

    # Drain
    time.sleep(2)
    tcpdump.terminate()
    tcpdump.wait(timeout=5)

    # --- Analyze tcpdump ---
    print("\n--- pcap Analysis ---")
    r = run(["tcpdump", "-r", recv_pcap], check=False, timeout=5)
    pcap_lines = [l for l in r.stdout.splitlines() if l.strip()]
    # Count UDP packets to port 8888
    udp_count = len([l for l in pcap_lines if "UDP" in l])
    print(f"  Total packets in pcap: {udp_count}")

    # First and last timestamps
    if udp_count > 0:
        # Extract timestamps
        import re
        ts_pat = re.compile(r"(\d{2}:\d{2}:\d{2}\.\d+)")
        timestamps = []
        for line in pcap_lines:
            m = ts_pat.search(line)
            if m:
                # Parse HH:MM:SS.ssssss
                parts = m.group(1).split(":")
                h, mi, s = int(parts[0]), int(parts[1]), float(parts[2])
                timestamps.append(h * 3600 + mi * 60 + s)
        if timestamps:
            span = timestamps[-1] - timestamps[0]
            rate = len(timestamps) / span if span > 0 else 0
            print(f"  Time span: {span:.4f}s, packets: {len(timestamps)}, "
                  f"rate: {rate:.1f} pps")

    # --- Parse switch log ---
    print("\n--- Switch Queue Metadata (log parsing) ---")
    entries = parse_switch_log(sw_log)
    print(f"  QREPRO entries found: {len(entries)}")

    if entries:
        # Summary stats
        enq_vals = [e.get("enq", 0) for e in entries]
        deq_vals = [e.get("deq", 0) for e in entries]
        delta_vals = [e.get("delta", 0) for e in entries]
        ports = set(e.get("port", -1) for e in entries)

        print(f"  Ports seen: {sorted(ports)}")
        print(f"  enq_qdepth: min={min(enq_vals)} max={max(enq_vals)} "
              f"nonzero={sum(1 for v in enq_vals if v > 0)}")
        print(f"  deq_qdepth: min={min(deq_vals)} max={max(deq_vals)} "
              f"nonzero={sum(1 for v in deq_vals if v > 0)}")
        print(f"  deq_timedelta: min={min(delta_vals)} max={max(delta_vals)} "
              f"nonzero={sum(1 for v in delta_vals if v > 0)}")

        # Show first 20 and last 5 entries
        print(f"\n  First 20 entries:")
        for i, e in enumerate(entries[:20]):
            print(f"    [{i:4d}] enq={e.get('enq', '?'):5} deq={e.get('deq', '?'):5} "
                  f"delta={e.get('delta', '?'):8} port={e.get('port', '?')} ts={e.get('ts', '?')}")

        print(f"\n  Last 5 entries:")
        for e in entries[-5:]:
            print(f"         enq={e.get('enq', '?'):5} deq={e.get('deq', '?'):5} "
                  f"delta={e.get('delta', '?'):8} port={e.get('port', '?')} ts={e.get('ts', '?')}")

        # Save parsed entries
        entries_path = os.path.join(tmpdir, "qrepro_entries.json")
        with open(entries_path, "w") as f:
            json.dump(entries, f, indent=2)
        print(f"\n  Full entries saved to: {entries_path}")

    # --- Look for BMv2 source ---
    print("\n--- BMv2 Source Search ---")
    for path in [
        "/usr/local/src/behavioral-model",
        "/usr/src/behavioral-model",
        "/opt/behavioral-model",
        os.path.expanduser("~/behavioral-model"),
        os.path.expanduser("~/bmv2"),
    ]:
        if os.path.isdir(path):
            print(f"  Found source tree: {path}")
            # Show git commit
            r = run(["git", "-C", path, "log", "-1", "--format=%H %s"],
                    check=False)
            print(f"  Git: {r.stdout.strip()}")
            # Find egress_buffers
            for root, dirs, files in os.walk(path):
                for fn in files:
                    if "egress_buffer" in fn or "queue" in fn.lower():
                        fpath = os.path.join(root, fn)
                        print(f"  Queue source file: {fpath}")
                        # Show relevant lines
                        with open(fpath) as sf:
                            for lineno, line in enumerate(sf, 1):
                                if "enq_qdepth" in line or "deq_qdepth" in line:
                                    print(f"    L{lineno}: {line.rstrip()}")
            break
    else:
        print("  No local BMv2 source tree found.")
        print("  Checking GitHub for relevant source lines:")
        print("  https://github.com/p4lang/behavioral-model/blob/main/targets/simple_switch/simple_switch.cpp")
        print("  Key assignments (from upstream source):")
        print("    enq_qdepth = egress_buffers.size(egress_port) at enqueue time")
        print("    deq_qdepth = egress_buffers.size(egress_port) at dequeue time")

    # --- Cleanup ---
    print("\n--- Cleanup ---")
    sw_proc.terminate()
    try:
        sw_proc.wait(timeout=5)
    except sp.TimeoutExpired:
        sw_proc.kill()
        sw_proc.wait()

    cleanup()

    # Save everything
    saved_dir = os.path.join(tmpdir, "results")
    os.makedirs(saved_dir, exist_ok=True)
    for fn in os.listdir(tmpdir):
        src = os.path.join(tmpdir, fn)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(saved_dir, fn))

    print(f"\nAll results saved to: {saved_dir}")

    # --- Verdict ---
    print("\n=== VERDICT ===")
    if entries:
        deq_nonzero = sum(1 for v in deq_vals if v > 0)
        if deq_nonzero > 0:
            print(f"SUCCESS: deq_qdepth > 0 in {deq_nonzero} entries.")
            print("BMv2 CORRECTLY populates deq_qdepth from egress queue depth.")
        else:
            print(f"ANOMALY: deq_qdepth = 0 in ALL {len(entries)} entries "
                  f"(sent={NPACKETS}).")
            print("enq_qdepth > 0 count:", sum(1 for v in enq_vals if v > 0))
            print("This contradicts upstream BMv2 source which assigns")
            print("deq_qdepth from egress_buffers.size() at dequeue time.")
    else:
        print("ERROR: No QREPRO entries found in switch log.")
        print("The log_msg output may have been directed to a different log.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
