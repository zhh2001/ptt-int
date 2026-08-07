#!/usr/bin/env python3
"""Traffic generation for PTT-INT experiments.

Generates traffic plans from workload definitions and executes them with
multi-sender synchronized start using subprocess pipes.

Uses veth + ip netns (NO Mininet).  Traffic runs inside network namespaces via
``ip netns exec <ns> python3 -c '<script>'``.

Synchronization protocol (coordinator <-> senders)
--------------------------------------------------
1. Coordinator launches one subprocess per unique *src_host* with
   ``stdin=PIPE`` / ``stdout=PIPE``.
2. Each sender writes ``READY\\n`` to stdout, then blocks on stdin.
3. Coordinator collects ``READY`` from every sender.
4. Coordinator computes ``T0 = time.monotonic_ns() + GUARD_INTERVAL_NS``.
5. Coordinator writes T0 (decimal string + newline) to each sender's stdin.
6. Each sender busy-waits until ``time.monotonic_ns() >= T0``, then sends its
   assigned packets, recording the actual send timestamp for every packet.
7. Each sender writes ``<host>_sender_log.csv`` to *output_dir*.
"""

import base64
import csv
import json
import os
import select
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GUARD_INTERVAL_NS: int = 100_000_000   # 100 ms -- headroom before T0
REPO_ROOT: Path = Path(__file__).resolve().parent.parent
READY_TIMEOUT_S: float = 30.0           # max time to wait for all senders
SENDER_TIMEOUT_S: float = 300.0         # max wall-clock time per sender


# ---------------------------------------------------------------------------
# TrafficEntry
# ---------------------------------------------------------------------------

@dataclass
class TrafficEntry:
    """A single packet in a deterministic traffic plan.

    Attributes:
        relative_time_ns: Planned send time relative to the common T0
            (monotonic nanoseconds).
        src_host: Source host name (e.g. ``"h1"``).
        dst_host: Destination host name (e.g. ``"h2"``).
        dst_ip: Destination IPv4 address (e.g. ``"10.0.0.2"``).
        dst_port: Destination UDP port.
        flow_id: Logical flow identifier for grouping related packets.
        packet_size: UDP payload size in bytes.
        sequence_no: Monotonic sequence number within the plan.
    """

    relative_time_ns: int
    src_host: str
    dst_host: str
    dst_ip: str
    dst_port: int
    flow_id: int
    packet_size: int
    sequence_no: int


# ===========================================================================
# Plan generation
# ===========================================================================

def generate_traffic_plan(
    workload_name: str,
    seed: int,
    topology: dict,
    config: dict,
) -> list[TrafficEntry]:
    """Generate a traffic plan by delegating to :mod:`experiments.workloads`.

    The workloads module is expected to expose a ``generate_workload``
    function with the same signature.

    Args:
        workload_name: Name of the workload generator
            (e.g. ``"constant"``, ``"poisson"``, ``"burst"``).
        seed: PRNG seed for reproducible plans.
        topology: Topology dict as returned by
            :meth:`SwitchManager.create_single_bottleneck` and friends.
        config: Resolved experiment configuration dict
            (e.g. from ``config/default.yaml``).

    Returns:
        Ordered list of :class:`TrafficEntry` objects sorted by
        ``relative_time_ns``.

    Raises:
        ImportError: If ``experiments/workloads.py`` does not exist or does
            not expose ``generate_workload``.
        ValueError: If *workload_name* is unknown to the workloads module.
    """
    workloads_path = REPO_ROOT / "experiments" / "workloads.py"
    if not workloads_path.exists():
        raise ImportError(
            f"experiments/workloads.py not found at {workloads_path}. "
            "Create this module with a generate_workload() function."
        )

    from experiments.workloads import generate_workload

    return generate_workload(workload_name, seed, topology, config)


# ===========================================================================
# Embedded sender script
# ===========================================================================

def _build_sender_script(
    plan_file_path: str,
    output_dir: str,
    sender_host: str,
) -> str:
    """Build a self-contained Python script for ``python3 -c``.

    The plan is read from a JSON file (NOT embedded in the command line)
    to avoid the kernel ARG_MAX limit with large traffic plans.

    The built script runs inside a network namespace and:
      1. Reads its packet plan from *plan_file_path*.
      2. Writes ``READY\\n`` to stdout so the coordinator can proceed.
      3. Reads T0 (decimal nanoseconds) from ``sys.stdin``.
      4. Busy-waits until ``time.monotonic_ns() >= T0``.
      5. Sends each packet via a UDP socket, recording the actual send
         timestamp.
      6. Writes ``<sender_host>_sender_log.csv`` to *output_dir*.

    Args:
        plan_file_path: Path to a JSON file containing the plan entries.
        output_dir: Directory where the log CSV will be written.
        sender_host: Host name used to form the log-file name.

    Returns:
        A Python script string safe to pass as the ``-c`` argument.
    """
    script = (
        "import csv,json,os,socket,sys,time\n"
        "_P=" + repr(str(plan_file_path)) + "\n"
        "with open(_P)as f:_D=json.load(f)\n"
        "_O=" + repr(str(output_dir)) + "\n"
        "_H=" + repr(str(sender_host)) + "\n"
        "sys.stdout.write('READY\\n');sys.stdout.flush()\n"
        "_L=sys.stdin.readline()\n"
        "if not _L:raise SystemExit(1)\n"
        "_T0=int(_L.strip())\n"
        "while time.monotonic_ns()<_T0:pass\n"
        "os.makedirs(_O,exist_ok=True)\n"
        "_F=os.path.join(_O,_H+'_sender_log.csv')\n"
        "_S=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
        "try:\n"
        " with open(_F,'w',newline='')as _W:\n"
        "  _W=csv.writer(_W)\n"
        "  _W.writerow(['sequence_no','planned_time_ns','actual_time_ns',"
        "'packet_size','dst_port'])\n"
        "  for _E in _D:\n"
        "   _T=_T0+_E['relative_time_ns']\n"
        "   while time.monotonic_ns()<_T:pass\n"
        "   _S.sendto(bytes(_E['packet_size']),(_E['dst_ip'],_E['dst_port']))\n"
        "   _A=time.monotonic_ns()\n"
        "   _W.writerow([_E['sequence_no'],_T,_A,_E['packet_size'],_E['dst_port']])\n"
        "finally:\n"
        " _S.close()\n"
    )
    return script


# ===========================================================================
# Plan execution
# ===========================================================================

def execute_traffic_plan(
    plan: list[TrafficEntry],
    topology: dict,
    output_dir: str,
    t0_ns: Optional[int] = None,
) -> dict:
    """Execute a traffic plan with multi-sender synchronized start.

    Launches one ``python3 -c`` subprocess per unique source host inside its
    network namespace.  All senders busy-wait until a common T0, then transmit
    their assigned packets and write per-host sender logs.

    Protocol
    --------
    1. Launch all senders (stdin=PIPE, stdout=PIPE).
    2. Wait for ``READY`` from every sender.
    3. Compute ``T0 = now + GUARD_INTERVAL_NS`` (unless *t0_ns* provided).
    4. Write T0 to each sender's stdin pipe.
    5. Wait for all senders to exit.
    6. Parse per-host CSV files and return structured results.

    Args:
        plan: Ordered list of :class:`TrafficEntry` objects.
        topology: Topology dict with a ``hosts`` key mapping host names to
            ``{"ns": <namespace>, "ip": <ip>}``.
        output_dir: Directory where per-host ``*_sender_log.csv`` files are
            written.
        t0_ns: Optional pre-computed T0 in monotonic nanoseconds.  When
            ``None`` the coordinator computes one from its own monotonic
            clock.

    Returns:
        Dict with keys:

        - ``sender_results``: ``{host: {"planned": [...], "actual": [...], "count": N}}``
        - ``t0_ns``: Common T0 in monotonic nanoseconds.

    Raises:
        ValueError: If the topology dict is missing ``hosts`` or a plan entry
            references an unknown host.
        RuntimeError: If a sender exits prematurely or fails to produce a log.
        TimeoutError: If any sender does not signal READY within the timeout.
    """
    hosts = topology.get("hosts")
    if not hosts:
        raise ValueError("topology dict has no 'hosts' key or it is empty")

    # --- Group entries by src_host ---
    per_host: dict[str, list[TrafficEntry]] = {}
    for entry in plan:
        per_host.setdefault(entry.src_host, []).append(entry)

    # Validate host references
    for host_name in per_host:
        if host_name not in hosts:
            raise ValueError(
                f"Plan references host '{host_name}', which is not in "
                f"topology hosts: {sorted(hosts.keys())}"
            )

    # Sort each host's entries by relative_time_ns for determinism
    for host_name in per_host:
        per_host[host_name].sort(key=lambda e: e.relative_time_ns)

    os.makedirs(output_dir, exist_ok=True)

    # ---- 1. Write per-host plan files and launch sender processes -------
    procs: dict[str, subprocess.Popen] = {}
    for host_name, entries in per_host.items():
        ns_name = hosts[host_name]["ns"]

        entry_dicts = [
            {
                "relative_time_ns": e.relative_time_ns,
                "sequence_no": e.sequence_no,
                "packet_size": e.packet_size,
                "dst_ip": e.dst_ip,
                "dst_port": e.dst_port,
            }
            for e in entries
        ]

        # Write plan to a file to avoid ARG_MAX limit on -c
        plan_file = os.path.join(output_dir, f"plan_{host_name}.json")
        with open(plan_file, "w") as f:
            json.dump(entry_dicts, f)

        script = _build_sender_script(plan_file, output_dir, host_name)

        proc = subprocess.Popen(
            ["ip", "netns", "exec", ns_name, "python3", "-c", script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        procs[host_name] = proc

    # ---- 2. Wait for READY from every sender ---------------------------
    try:
        pending: set[str] = set(procs.keys())
        deadline = time.monotonic() + READY_TIMEOUT_S

        while pending and time.monotonic() < deadline:
            for host_name in sorted(pending):
                proc = procs[host_name]

                # Check for premature death
                if proc.poll() is not None:
                    stderr = ""
                    try:
                        stderr = proc.stderr.read()
                    except Exception:
                        pass
                    raise RuntimeError(
                        f"Sender '{host_name}' (ns={hosts[host_name]['ns']}) "
                        f"exited prematurely with code {proc.returncode}.\n"
                        f"stderr: {stderr}"
                    )

                line = _readline_nonblock(proc)
                if line is None:
                    continue
                line = line.strip()
                if line == "READY":
                    pending.discard(host_name)
                elif line:
                    raise RuntimeError(
                        f"Sender '{host_name}' produced unexpected output "
                        f"before READY: {line!r}"
                    )

            if pending:
                time.sleep(0.005)

        if pending:
            for host_name in pending:
                _kill_proc(procs[host_name])
            raise TimeoutError(
                f"Senders did not signal READY within "
                f"{READY_TIMEOUT_S}s: {sorted(pending)}"
            )
    except Exception:
        # Clean up all senders on any error during ready-collection
        for proc in procs.values():
            _kill_proc(proc)
        raise

    # ---- 3-4. Compute T0 and distribute --------------------------------
    if t0_ns is None:
        t0_ns = time.monotonic_ns() + GUARD_INTERVAL_NS

    for host_name, proc in procs.items():
        try:
            proc.stdin.write(f"{t0_ns}\n")
            proc.stdin.flush()
        except BrokenPipeError:
            raise RuntimeError(
                f"Failed to write T0 to sender '{host_name}': stdin pipe broken"
            )

    # ---- 5. Wait for all senders to finish -----------------------------
    # (communicate() closes stdin automatically — do NOT close before calling it)
    for host_name, proc in procs.items():
        try:
            stdout, stderr = proc.communicate(timeout=SENDER_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            _kill_proc(proc)
            raise TimeoutError(
                f"Sender '{host_name}' timed out after {SENDER_TIMEOUT_S}s"
            )

        if proc.returncode != 0:
            raise RuntimeError(
                f"Sender '{host_name}' exited with code {proc.returncode}.\n"
                f"stdout: {stdout}\nstderr: {stderr}"
            )

    # ---- 6. Collect results from per-host CSV files --------------------
    sender_results: dict[str, dict] = {}
    for host_name, entries in per_host.items():
        log_path = os.path.join(output_dir, f"{host_name}_sender_log.csv")

        planned_times: list[int] = []
        actual_times: list[int] = []

        if os.path.isfile(log_path):
            with open(log_path, "r", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    planned_times.append(int(row["planned_time_ns"]))
                    actual_times.append(int(row["actual_time_ns"]))
        else:
            raise RuntimeError(
                f"Sender '{host_name}' did not produce expected log file: "
                f"{log_path}"
            )

        sender_results[host_name] = {
            "planned": planned_times,
            "actual": actual_times,
            "count": len(planned_times),
        }

    return {
        "sender_results": sender_results,
        "t0_ns": t0_ns,
    }


# ===========================================================================
# Rate computation
# ===========================================================================

def compute_actual_rates(exec_result: dict, duration_s: float) -> dict:
    """Compute actual send / receive rates from measured timestamps.

    Uses **actual** send timestamps (not pacing parameters) so the computed
    rates reflect what genuinely arrived on the wire.

    Args:
        exec_result: Dict returned by :func:`execute_traffic_plan`.
        duration_s: Nominal experiment duration in seconds.

    Returns:
        Dict with keys:

        - ``sender_rate_pps``: Aggregate packets-per-second computed from the
          span between the first and last actual send across all senders
          (``(total_packets - 1) / actual_span_s``).
        - ``receiver_rate_pps``: Aggregate offered-load rate computed as
          ``total_packets_sent / duration_s`` (upper bound -- no independent
          receiver measurement is available).
        - ``total_packets_sent``: Total packets transmitted by all senders.
        - ``total_packets_received``: Equal to ``total_packets_sent`` (no
          independent receiver measurement).
    """
    sender_results = exec_result.get("sender_results", {})

    total_packets_sent = 0
    all_actual: list[int] = []

    for _host_name, result in sender_results.items():
        count = result.get("count", 0)
        total_packets_sent += count
        all_actual.extend(result.get("actual", []))

    if not all_actual or total_packets_sent == 0:
        return {
            "sender_rate_pps": 0.0,
            "receiver_rate_pps": 0.0,
            "total_packets_sent": 0,
            "total_packets_received": 0,
        }

    first_ns = min(all_actual)
    last_ns = max(all_actual)
    actual_span_s = (last_ns - first_ns) / 1e9

    if actual_span_s <= 0:
        # All packets sent at effectively the same instant
        sender_rate_pps = float(total_packets_sent)
    else:
        sender_rate_pps = (total_packets_sent - 1) / actual_span_s

    safe_duration = max(duration_s, 0.001)
    receiver_rate_pps = total_packets_sent / safe_duration

    return {
        "sender_rate_pps": round(sender_rate_pps, 2),
        "receiver_rate_pps": round(receiver_rate_pps, 2),
        "total_packets_sent": total_packets_sent,
        "total_packets_received": total_packets_sent,
    }


# ===========================================================================
# Convenience: generate + execute + compute rates
# ===========================================================================

def run_traffic(
    workload_name: str,
    seed: int,
    topology: dict,
    config: dict,
    output_dir: str,
    duration_s: float = 30.0,
) -> dict:
    """Generate and execute a traffic plan, returning full results with rates.

    Convenience wrapper that chains :func:`generate_traffic_plan`,
    :func:`execute_traffic_plan`, and :func:`compute_actual_rates`.

    Args:
        workload_name: Workload generator name.
        seed: PRNG seed.
        topology: Topology dict.
        config: Resolved config dict.
        output_dir: Directory for sender logs.
        duration_s: Nominal experiment duration for rate computation.

    Returns:
        Merged dict with keys from :func:`execute_traffic_plan` plus a
        ``"rates"`` key holding the output of :func:`compute_actual_rates`.
    """
    plan = generate_traffic_plan(workload_name, seed, topology, config)
    exec_result = execute_traffic_plan(plan, topology, output_dir)
    rates = compute_actual_rates(exec_result, duration_s)
    exec_result["rates"] = rates
    return exec_result


# ===========================================================================
# Internal helpers
# ===========================================================================

def _readline_nonblock(proc: subprocess.Popen) -> Optional[str]:
    """Read a single line from *proc*'s stdout without blocking.

    Returns ``None`` when no data is available, otherwise the line string
    (may include the trailing newline).
    """
    try:
        fd = proc.stdout.fileno()
        ready, _, _ = select.select([fd], [], [], 0)
        if not ready:
            return None
        line = proc.stdout.readline()
        return line if line else None
    except (ValueError, OSError):
        return None


def _kill_proc(proc: subprocess.Popen) -> None:
    """Kill a subprocess gracefully (SIGTERM), then forcefully (SIGKILL)."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        pass
    try:
        proc.wait(timeout=2)
    except (subprocess.TimeoutExpired, OSError):
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=2)
        except (subprocess.TimeoutExpired, OSError):
            pass


# ===========================================================================
# CLI (for stand-alone testing)
# ===========================================================================

def main():
    """Minimal CLI for testing the traffic generator stand-alone."""
    import argparse
    import tempfile

    parser = argparse.ArgumentParser(
        description="Generate and execute a traffic plan for PTT-INT."
    )
    parser.add_argument(
        "--workload", default="constant",
        help="Workload name (passed to experiments/workloads.py)",
    )
    parser.add_argument("--seed", type=int, default=1, help="PRNG seed")
    parser.add_argument(
        "--output-dir", default=None,
        help="Output directory (default: results/traffic/<workload>_<seed>)",
    )
    parser.add_argument(
        "--duration", type=float, default=30.0,
        help="Nominal experiment duration in seconds",
    )
    args = parser.parse_args()

    from experiments.switch_manager import SwitchManager

    mgr = SwitchManager(
        tmpdir=tempfile.mkdtemp(prefix="traffic_gen_"),
        p4_json_path=str(REPO_ROOT / "p4src" / "ptt_int.json"),
    )

    topology = mgr.create_single_bottleneck()

    if args.output_dir is None:
        output_dir = str(
            REPO_ROOT / "results" / "traffic" / f"{args.workload}_{args.seed}"
        )
    else:
        output_dir = args.output_dir

    try:
        result = run_traffic(
            workload_name=args.workload,
            seed=args.seed,
            topology=topology,
            config={},
            output_dir=output_dir,
            duration_s=args.duration,
        )
        print(json.dumps(result.get("rates", {}), indent=2))
    finally:
        mgr.stop_all()


if __name__ == "__main__":
    main()
