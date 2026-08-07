#!/usr/bin/env python3
"""Gate C: TCP Problem Classification.

Classifies why TCP doesn't work through BMv2 P4 switches by systematic
isolation testing.

Test 1: Plain IPv4/TCP forwarding through P4 program in BYPASS mode
        (telemetry FULLY disabled, scheme_mode=7).
        - Python socket-based TCP connect/listen between h1 and h2
        - tcpdump on ALL interfaces to trace each segment

Test 2: Telemetry insertion effects on TCP
        - Repeat with scheme_mode=6 (PTT)
        - Compare: does PTT header insertion change packet behavior?

Classification outcome (one of):
  1. TCP works in BYPASS mode → issue is telemetry header insertion
  2. TCP fails in BYPASS mode → P4 parser/routing issue, not telemetry
  3. TCP SYN reaches h2 but SYN-ACK never returns → routing asymmetry
  4. TCP SYN never reaches h2 → P4 parser dropping non-UDP packets
  5. TCP works end-to-end → previous diagnosis was "iperf3 usage error"

Output: tcp_diagnosis_report.md with traces and definitive classification.
"""

import sys
import os
import time
import json
import argparse
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from experiments.switch_manager import SwitchManager


def _run(cmd, **kwargs):
    kwargs.setdefault("text", True)
    kwargs.setdefault("timeout", 30)
    kwargs.setdefault("capture_output", True)
    return subprocess.run(cmd, **kwargs)


def test_tcp_connect(src_ns: str, dst_ip: str, dst_port: int,
                     timeout_s: float = 10.0) -> dict:
    """Attempt a TCP connection from src_ns to dst_ip:dst_port.

    Uses Python sockets for both client and server within namespaces.

    Returns dict with: success, client_output, server_output, error.
    """
    # Start a simple TCP server in the destination namespace
    server_script = f"""
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {dst_port}))
s.listen(1)
s.settimeout({timeout_s})
print("LISTENING", flush=True)
try:
    conn, addr = s.accept()
    data = conn.recv(1024)
    print(f"RECEIVED: {{data.decode(errors='replace')}}", flush=True)
    conn.sendall(b"ACK")
    conn.close()
except socket.timeout:
    print("TIMEOUT", flush=True)
except Exception as e:
    print(f"ERROR: {{e}}", flush=True)
finally:
    s.close()
"""

    client_script = f"""
import socket, time, sys
time.sleep(0.5)  # wait for server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout({timeout_s})
try:
    s.connect(("{dst_ip}", {dst_port}))
    s.sendall(b"PING")
    data = s.recv(1024)
    print(f"RECEIVED: {{data.decode(errors='replace')}}", flush=True)
    s.close()
    print("SUCCESS", flush=True)
except socket.timeout:
    print("TIMEOUT", flush=True)
except ConnectionRefusedError:
    print("CONNECTION_REFUSED", flush=True)
except OSError as e:
    print(f"OS_ERROR: {{e}}", flush=True)
"""

    server_proc = subprocess.Popen(
        ["ip", "netns", "exec", src_ns, "python3", "-c", server_script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )

    # Wait for server to be ready
    time.sleep(0.5)

    client_proc = subprocess.Popen(
        ["ip", "netns", "exec", src_ns, "python3", "-c", client_script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )

    try:
        client_stdout, client_stderr = client_proc.communicate(timeout=timeout_s + 5)
    except subprocess.TimeoutExpired:
        client_proc.kill()
        client_stdout, client_stderr = client_proc.communicate()

    try:
        server_stdout, server_stderr = server_proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        server_proc.kill()
        server_stdout, server_stderr = server_proc.communicate()

    success = "SUCCESS" in client_stdout
    return {
        "success": success,
        "client_stdout": client_stdout.strip(),
        "server_stdout": server_stdout.strip(),
        "client_stderr": client_stderr.strip(),
        "server_stderr": server_stderr.strip(),
    }


def run_tcp_diagnosis(output_dir: str, p4_json: str = None) -> dict:
    """Run full TCP diagnosis across BYPASS and PTT modes.

    Returns dict with classification and evidence.
    """
    if p4_json is None:
        p4_json = str(REPO_ROOT / "p4src" / "ptt_int.json")

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    tmpdir = tempfile.mkdtemp(prefix="ptt_tcp_")
    results = {}
    pcaps_dir = output_dir / "pcaps"
    pcaps_dir.mkdir(exist_ok=True)

    for mode_name, scheme_mode in [("BYPASS", 7), ("PTT", 6)]:
        print(f"\n=== Test: {mode_name} mode (scheme_mode={scheme_mode}) ===")

        try:
            mgr = SwitchManager(tmpdir=str(tmpdir), p4_json_path=p4_json)
            topo = mgr.create_single_bottleneck()

            # Configure switches
            routes = mgr.get_default_routes()
            for sw_name, sw_info in topo["switches"].items():
                mgr.configure_switch(
                    sw_info["thrift_port"], sw_info["device_id"],
                    scheme_mode,
                    routes.get(sw_name, []),
                )
                # Unlimited queues for TCP test (no bottleneck)
                for port_idx, _ in sw_info["interfaces"]:
                    mgr.set_queue(sw_info["thrift_port"], port_idx, 128, 0)

            # Start tcpdump on all interfaces
            tcpdump_procs = []
            for host_name, host_info in topo["hosts"].items():
                ns = host_info["ns"]
                iface = host_info["iface"]
                pcap_path = pcaps_dir / f"tcp_{mode_name}_{host_name}.pcap"
                proc = subprocess.Popen(
                    ["ip", "netns", "exec", ns,
                     "tcpdump", "-i", iface, "-w", str(pcap_path), "-U"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                tcpdump_procs.append(proc)

            time.sleep(0.5)

            # Get h1 and h2 info
            h1_ns = topo["hosts"]["h1"]["ns"]
            h2_ip = topo["hosts"]["h2"]["ip"].split("/")[0]

            # Test TCP from h1 (client+server both in h1 for simplicity,
            # but we actually want h1→h2. Let's do server in h2, client in h1)
            h2_ns = topo["hosts"]["h2"]["ns"]

            # Start server in h2
            server_script = f"""
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9999))
s.listen(1)
s.settimeout(10)
print("LISTENING", flush=True)
try:
    conn, addr = s.accept()
    data = conn.recv(1024)
    print(f"RECEIVED: {{data.decode(errors='replace')}} from {{addr}}", flush=True)
    conn.sendall(b"TCP_ACK_FROM_SERVER")
    conn.close()
except socket.timeout:
    print("TIMEOUT", flush=True)
except Exception as e:
    print(f"ERROR: {{e}}", flush=True)
finally:
    s.close()
"""
            server_proc = subprocess.Popen(
                ["ip", "netns", "exec", h2_ns, "python3", "-c", server_script],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            time.sleep(0.8)

            # Start client in h1
            client_script = f"""
import socket, time
time.sleep(0.3)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
try:
    s.connect(("{h2_ip}", 9999))
    s.sendall(b"TCP_PING_FROM_CLIENT")
    data = s.recv(1024)
    print(f"RECEIVED: {{data.decode(errors='replace')}}", flush=True)
    s.close()
    print("SUCCESS", flush=True)
except socket.timeout:
    print("TIMEOUT", flush=True)
except ConnectionRefusedError:
    print("CONNECTION_REFUSED", flush=True)
except OSError as e:
    print(f"OS_ERROR: {{e}}", flush=True)
"""
            client_proc = subprocess.Popen(
                ["ip", "netns", "exec", h1_ns, "python3", "-c", client_script],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )

            try:
                client_stdout, client_stderr = client_proc.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                client_proc.kill()
                client_stdout, client_stderr = client_proc.communicate()

            try:
                server_stdout, server_stderr = server_proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_stdout, server_stderr = server_proc.communicate()

            tcp_success = "SUCCESS" in client_stdout
            server_received = "RECEIVED" in server_stdout

            # Stop tcpdump
            for proc in tcpdump_procs:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()

            results[mode_name] = {
                "scheme_mode": scheme_mode,
                "tcp_success": tcp_success,
                "server_received": server_received,
                "client_stdout": client_stdout.strip(),
                "server_stdout": server_stdout.strip(),
                "client_stderr": client_stderr.strip()[:500],
                "server_stderr": server_stderr.strip()[:500],
            }

            print(f"  TCP success: {tcp_success}")
            print(f"  Server received: {server_received}")
            print(f"  Client output: {client_stdout.strip()[:200]}")
            print(f"  Server output: {server_stdout.strip()[:200]}")

            mgr.stop_all()

        except Exception as e:
            print(f"  ERROR in {mode_name} test: {e}")
            results[mode_name] = {"error": str(e)}

    shutil.rmtree(tmpdir, ignore_errors=True)

    # ── Classification ───────────────────────────────────────────────
    bypass = results.get("BYPASS", {})
    ptt = results.get("PTT", {})

    bypass_ok = bypass.get("tcp_success", False)
    ptt_ok = ptt.get("tcp_success", False)
    bypass_server = bypass.get("server_received", False)
    ptt_server = ptt.get("server_received", False)

    if bypass_ok and ptt_ok:
        classification = "TCP_WORKS"
        diagnosis = (
            "TCP works end-to-end in both BYPASS and PTT modes. "
            "Previous TCP issues were likely due to iperf3 usage error, "
            "not a fundamental P4/TCP incompatibility."
        )
    elif bypass_ok and not ptt_ok:
        classification = "TELEMETRY_INSERTION_ISSUE"
        diagnosis = (
            "TCP works in BYPASS mode (no telemetry) but fails in PTT mode. "
            "PTT header insertion likely causes MTU issues (packet size exceeds "
            "MTU after adding PTT shim + hop records) or breaks TCP checksums."
        )
    elif not bypass_ok and not ptt_ok:
        if bypass_server:
            classification = "ROUTING_ASYMMETRY"
            diagnosis = (
                "TCP SYN reaches h2 (server receives data) but client never "
                "gets the SYN-ACK. This suggests routing asymmetry — forward "
                "path works but return path doesn't."
            )
        else:
            classification = "P4_PARSER_ISSUE"
            diagnosis = (
                "TCP SYN never reaches h2 even in BYPASS mode. The P4 parser "
                "may be dropping non-UDP packets. Check parser implementation "
                "for TCP/IPv4 handling."
            )
    else:
        classification = "INCONCLUSIVE"
        diagnosis = "Unexpected result combination. Review raw outputs."

    report = {
        "classification": classification,
        "diagnosis": diagnosis,
        "bypass_results": bypass,
        "ptt_results": ptt,
        "timestamp": datetime.now().isoformat(),
    }

    # Save report
    with open(output_dir / "tcp_diagnosis_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)

    # Generate Markdown report
    md = _generate_md_report(report)
    with open(output_dir / "tcp_diagnosis_report.md", "w") as f:
        f.write(md)

    print(f"\n=== Gate C Classification: {classification} ===")
    print(f"Diagnosis: {diagnosis}")
    print(f"Report: {output_dir / 'tcp_diagnosis_report.md'}")

    return report


def _generate_md_report(report: dict) -> str:
    """Generate Markdown TCP diagnosis report."""
    md = f"""# Gate C: TCP Problem Classification Report

**Date:** {report['timestamp']}
**Classification:** `{report['classification']}`

## Diagnosis

{report['diagnosis']}

## Test Results

### BYPASS Mode (scheme_mode=7, telemetry fully disabled)

```
TCP success: {report['bypass_results'].get('tcp_success', 'N/A')}
Server received: {report['bypass_results'].get('server_received', 'N/A')}
Client stdout: {report['bypass_results'].get('client_stdout', 'N/A')[:500]}
Server stdout: {report['bypass_results'].get('server_stdout', 'N/A')[:500]}
```

### PTT Mode (scheme_mode=6, predictive telemetry)

```
TCP success: {report['ptt_results'].get('tcp_success', 'N/A')}
Server received: {report['ptt_results'].get('server_received', 'N/A')}
Client stdout: {report['ptt_results'].get('client_stdout', 'N/A')[:500]}
Server stdout: {report['ptt_results'].get('server_stdout', 'N/A')[:500]}
```

## Classification Legend

| Code | Meaning |
|------|---------|
| `TCP_WORKS` | TCP works end-to-end; previous issues were iperf3-related |
| `TELEMETRY_INSERTION_ISSUE` | TCP works without telemetry, fails with PTT headers → MTU/checksum issue |
| `ROUTING_ASYMMETRY` | Server receives SYN but client gets no SYN-ACK → return path broken |
| `P4_PARSER_ISSUE` | TCP SYN never reaches server → P4 parser drops non-UDP packets |

## Evidence

Raw tcpdump pcaps are available in `pcaps/` directory.

Gate C does NOT block experiments — it classifies the issue for the paper.
"""
    return md


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Gate C: TCP Problem Classification")
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "results" / "tcp_diagnosis"),
                        help="Output directory for diagnosis report")
    parser.add_argument("--p4-json", default=None,
                        help="Path to compiled P4 JSON")
    args = parser.parse_args()

    report = run_tcp_diagnosis(
        output_dir=args.output_dir,
        p4_json=args.p4_json,
    )
    print(f"\nClassification: {report['classification']}")


if __name__ == "__main__":
    main()
