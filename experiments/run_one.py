#!/usr/bin/env python3
"""Run a single PTT-INT experiment.

Orchestrates end-to-end:

1.  Create temp directory for this run (or use provided output_dir)
2.  Create SwitchManager(tmpdir, p4_json_path)
3.  Call appropriate create_* method based on topology arg
4.  Start all simple_switch processes per topology spec
5.  Wait for all Thrift servers
6.  Configure all switches: switch_id from config, scheme_mode from SCHEME_MAP,
    bidirectional routes
7.  Set queue depth=128 on all ports; set queue_rate on bottleneck egress ports
8.  Generate traffic plan from workload registry
9.  Start tcpdump on all host interfaces
10. Determine common monotonic T0; execute all senders synchronized
11. Wait for all senders to complete + drain period
12. Stop tcpdump; collect pcaps
13. Copy switch log files from tmpdir
14. Read Gate B sampling counters from bottleneck ports
15. Stop topology (teardown everything)
16. Post-process: parse_pcap_to_csv, parse_bmv2_log, detect_events,
    compute_all_metrics, compute_actual_rates
17. Save manifest via create_manifest + save_manifest
18. Save config_resolved.yaml
19. Save gate_b_counters.json
20. Run sanity checks (warnings only, never abort)
21. Return output_dir path

NO Mininet dependency.  Uses SwitchManager + TrafficGenerator exclusively.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

# ---------------------------------------------------------------------------
# Project root
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# ---------------------------------------------------------------------------
# Scheme name -> register value
# ---------------------------------------------------------------------------

SCHEME_MAP: dict[str, int] = {
    "FULL": 0,
    "PERIODIC_4": 1,
    "PERIODIC_16": 2,
    "PERIODIC_32": 3,
    "REACTIVE": 4,
    "DELTA": 5,
    "PTT": 6,
    "BYPASS": 7,
}

SCHEME_NAMES: dict[int, str] = {v: k for k, v in SCHEME_MAP.items()}


# ===========================================================================
# Config loading
# ===========================================================================


def load_config(config_path: Optional[str] = None) -> dict:
    """Load experiment configuration from a YAML file.

    Args:
        config_path: Path to YAML config.  Defaults to ``config/default.yaml``
            relative to the repository root.

    Returns:
        Parsed configuration dictionary.
    """
    if config_path is None:
        config_path = REPO_ROOT / "config" / "default.yaml"
    with open(config_path) as f:
        return yaml.safe_load(f)


# ===========================================================================
# Route construction
# ===========================================================================


def _build_routes(topo: dict, topology_name: str) -> dict[str, list[dict]]:
    """Build bidirectional LPM routes for every switch in *topo*.

    Returns a dict mapping switch name to a list of route dicts, each with
    keys ``dst_ip`` (CIDR string) and ``port`` (int).

    The routes encode the full forwarding path so that traffic can flow
    between every pair of hosts in both directions.
    """
    routes: dict[str, list[dict]] = {}

    hosts = topo["hosts"]
    switches = topo["switches"]

    # Collect host IPs (strip the /prefix)
    host_ips: dict[str, str] = {}
    for name, info in hosts.items():
        host_ips[name] = info["ip"].split("/")[0]

    if topology_name == "single_bottleneck":
        # h1---s1---s2---h2
        # s1: port 0 = h1, port 1 = towards s2
        # s2: port 0 = towards s1, port 1 = h2
        h1_ip = host_ips.get("h1", "10.0.0.1")
        h2_ip = host_ips.get("h2", "10.0.0.2")
        routes["s1"] = [
            {"dst_ip": f"{h1_ip}/32", "port": 0},
            {"dst_ip": f"{h2_ip}/32", "port": 1},
        ]
        routes["s2"] = [
            {"dst_ip": f"{h1_ip}/32", "port": 0},
            {"dst_ip": f"{h2_ip}/32", "port": 1},
        ]

    elif topology_name == "incast":
        # Senders h1..hN -> s1 -> s2 -> receiver
        # s1: ports 0..N-1 = senders, port N = link to s2
        # s2: port 0 = link to s1, port 1 = receiver
        s1_ifaces = switches["s1"]["interfaces"]  # (port, veth)
        n_senders = len(s1_ifaces) - 1  # last port is s1-s2 link

        s1_routes: list[dict] = []
        for i in range(1, n_senders + 1):
            sender_name = f"h{i}"
            sender_ip = host_ips.get(sender_name)
            if sender_ip:
                s1_routes.append({"dst_ip": f"{sender_ip}/32", "port": i - 1})
        recv_ip = host_ips.get("receiver", "10.0.0.254")
        s1_routes.append({"dst_ip": f"{recv_ip}/32", "port": n_senders})
        routes["s1"] = s1_routes

        s2_routes: list[dict] = []
        for i in range(1, n_senders + 1):
            sender_ip = host_ips.get(f"h{i}")
            if sender_ip:
                s2_routes.append({"dst_ip": f"{sender_ip}/32", "port": 0})
        s2_routes.append({"dst_ip": f"{recv_ip}/32", "port": 1})
        routes["s2"] = s2_routes

    elif topology_name == "leaf_spine":
        # n_leaf x n_spine.  Determine sizes from switch names.
        leaf_names = sorted(
            [s for s in switches if s.startswith("leaf")],
        )
        spine_names = sorted(
            [s for s in switches if s.startswith("spine")],
        )
        n_leaf = len(leaf_names)
        n_spine = len(spine_names)

        # Collect leaf host IPs (one host per leaf by convention)
        leaf_host_ips: dict[int, str] = {}
        for leaf_idx in range(n_leaf):
            host_name = f"h{leaf_idx + 1}"
            if host_name in host_ips:
                leaf_host_ips[leaf_idx] = host_ips[host_name]

        # Leaf routing: local host on port 0, remote hosts via spine0 (port 1)
        for leaf_idx, leaf_name in enumerate(leaf_names):
            leaf_routes: list[dict] = []
            local_ip = leaf_host_ips.get(leaf_idx)
            if local_ip:
                leaf_routes.append({"dst_ip": f"{local_ip}/32", "port": 0})
            for remote_idx, remote_ip in leaf_host_ips.items():
                if remote_idx == leaf_idx:
                    continue
                # Use spine0 uplink (port 1) as primary path
                leaf_routes.append({"dst_ip": f"{remote_ip}/32", "port": 1})
            routes[leaf_name] = leaf_routes

        # Spine routing: each spine connects to all leaves
        for spine_idx, spine_name in enumerate(spine_names):
            spine_routes: list[dict] = []
            for leaf_idx in range(n_leaf):
                leaf_ip = leaf_host_ips.get(leaf_idx)
                if leaf_ip:
                    # Spine port ``leaf_idx`` connects to leaf ``leaf_idx``
                    spine_routes.append(
                        {"dst_ip": f"{leaf_ip}/32", "port": leaf_idx},
                    )
            routes[spine_name] = spine_routes

    else:
        raise ValueError(f"Unknown topology: {topology_name}")

    return routes


# ===========================================================================
# Sanity checks
# ===========================================================================


def _sanity_checks(
    output_dir: Path,
    topo: dict,
    scheme: str,
    oracle_entries: int,
    manifest: dict,
    sender_total: int,
    pcap_path: Optional[Path],
) -> None:
    """Run post-experiment sanity checks, printing warnings to stderr.

    Never aborts -- function signature forces the caller to check stderr.
    """

    def warn(msg: str) -> None:
        print(f"  SANITY WARNING: {msg}", file=sys.stderr)

    # 1. Sender packets > 0
    if sender_total == 0:
        warn("no sender packets recorded (sender_total=0)")

    # 2. Receiver packets > 0  (check pcap file size)
    if pcap_path is None or not pcap_path.exists():
        warn("no capture.pcap found")
    elif pcap_path.stat().st_size == 0:
        warn("capture.pcap is empty (zero bytes)")

    # 3. Oracle rows > 0
    if oracle_entries == 0:
        warn("oracle.csv is empty -- no PTT_ORACLE lines in switch logs")

    # 4. Monotonic timestamps within source (check oracle.csv)
    oracle_csv = output_dir / "oracle.csv"
    if oracle_csv.exists():
        try:
            with open(oracle_csv) as f:
                reader = csv.DictReader(f)
                prev_ts: dict[tuple, int] = {}
                for row in reader:
                    key = (int(row["switch_id"]), int(row["port"]))
                    ts = int(row["ts_us"])
                    if key in prev_ts and ts < prev_ts[key]:
                        warn(
                            f"non-monotonic oracle timestamp: sw={key[0]} "
                            f"port={key[1]} ts={ts} after {prev_ts[key]}"
                        )
                    prev_ts[key] = ts
        except Exception:
            pass

    # 5. q in [0, 128]
    if oracle_csv.exists():
        try:
            with open(oracle_csv) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    q = int(row["q"])
                    if q < 0 or q > 128:
                        warn(f"oracle q={q} out of range [0,128]")
        except Exception:
            pass

    # 6. state in {0, 1, 2}
    if oracle_csv.exists():
        try:
            with open(oracle_csv) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    state = int(row["state"])
                    if state not in (0, 1, 2):
                        warn(f"oracle state={state} not in {{0,1,2}}")
        except Exception:
            pass

    # 7. scheme mode matches manifest
    manifest_scheme = manifest.get("scheme")
    if manifest_scheme and manifest_scheme != scheme:
        warn(
            f"manifest scheme '{manifest_scheme}' != "
            f"CLI scheme '{scheme}'"
        )


def _kill_stale_switches() -> None:
    """Kill stale simple_switch processes and clean up leftover namespaces/veths."""
    # Kill stale switch processes
    try:
        result = subprocess.run(
            ["pgrep", "-f", "simple_switch"],
            capture_output=True, text=True, timeout=5,
        )
        pids = result.stdout.strip().split()
        if pids:
            print(f"  Killing {len(pids)} stale simple_switch process(es): "
                  f"{' '.join(pids)}")
            subprocess.run(
                ["pkill", "-f", "simple_switch"],
                timeout=5, check=False,
            )
            time.sleep(0.5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Clean up leftover namespaces from previous crashed runs
    try:
        result = subprocess.run(
            ["ip", "netns", "list"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.strip().splitlines():
            ns_name = line.split()[0].strip()
            if ns_name.startswith("ptt_ns_"):
                subprocess.run(
                    ["ip", "netns", "delete", ns_name],
                    timeout=5, check=False,
                )
                print(f"  Deleted stale namespace: {ns_name}")
        time.sleep(0.2)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Clean up leftover veth pairs
    for prefix in ["s1_", "s2_", "h1_", "h2_", "leaf", "spine", "recv_"]:
        try:
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if line.strip().startswith(prefix):
                    iface = line.strip().split(":")[1].strip().split("@")[0]
                    subprocess.run(
                        ["ip", "link", "delete", iface],
                        timeout=5, check=False,
                    )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass


# ===========================================================================
# Main experiment function
# ===========================================================================


def run_experiment(
    scheme: str = "PTT",
    seed: int = 1,
    workload: str = "ramp_medium",
    topology_name: str = "single_bottleneck",
    duration_s: float = 30.0,
    output_dir: Optional[str] = None,
    config: Optional[dict] = None,
    bottleneck_rate_pps: int = 100,
    packet_size: int = 1000,
    int_port: int = 32768,
    tmpdir: Optional[str] = None,
    warmup_s: float = 2.0,
    drain_s: float = 2.0,
) -> str:
    """Run a single PTT-INT experiment end-to-end.

    Returns:
        Absolute path to the output directory containing all artifacts.
    """
    # ------------------------------------------------------------------
    # 0.  Setup
    # ------------------------------------------------------------------

    if config is None:
        config = load_config()

    scheme_mode = SCHEME_MAP.get(scheme)
    if scheme_mode is None:
        print(f"ERROR: unknown scheme '{scheme}'", file=sys.stderr)
        sys.exit(1)

    # Kill any stale simple_switch processes from previous crashed runs
    _kill_stale_switches()

    # Resolve output directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"{scheme}_{workload}_seed{seed}_{ts}"
    if output_dir is None:
        output_dir = str(
            REPO_ROOT
            / "results" / "raw"
            / topology_name / scheme / workload
            / str(seed)
        )
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(
        f"=== Experiment: scheme={scheme} ({scheme_mode}) "
        f"workload={workload} seed={seed} ==="
    )
    print(f"    Output: {output_dir}")

    # Resolve P4 JSON path
    p4_json = str(REPO_ROOT / "p4src" / "ptt_int.json")
    if not os.path.exists(p4_json):
        raise FileNotFoundError(
            f"P4 JSON not found: {p4_json}.  Run scripts/build.sh first."
        )

    # Temp working directory for switch artifacts
    if tmpdir is None:
        tmpdir = tempfile.mkdtemp(prefix="ptt_experiment_")
    run_tmp = Path(tmpdir) / run_id
    run_tmp.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Import heavy modules (after sys.path setup)
    # ------------------------------------------------------------------

    from experiments.switch_manager import SwitchManager
    from experiments.traffic_generator import (
        generate_traffic_plan,
        execute_traffic_plan,
        compute_actual_rates,
    )
    from experiments.manifest import create_manifest, save_manifest
    from collector.parse_pcap import parse_pcap_to_csv
    from oracle.parse_bmv2_log import parse_bmv2_log
    from oracle.events import detect_events, write_events_csv

    # ------------------------------------------------------------------
    # 1-3.  Create SwitchManager + topology
    # ------------------------------------------------------------------

    mgr = SwitchManager(tmpdir=str(run_tmp), p4_json_path=p4_json)

    print("Creating topology ...")
    if topology_name == "single_bottleneck":
        topo = mgr.create_single_bottleneck()
    elif topology_name == "incast":
        topo = mgr.create_incast(n_senders=4)
    elif topology_name == "leaf_spine":
        topo = mgr.create_leaf_spine()
    else:
        raise ValueError(f"Unknown topology: {topology_name}")

    # ------------------------------------------------------------------
    # 4.  Start all simple_switch processes
    # ------------------------------------------------------------------

    print("Starting switches ...")
    for sw_name, sw_info in topo["switches"].items():
        mgr.start_switch(
            name=sw_name,
            thrift_port=sw_info["thrift_port"],
            device_id=sw_info["device_id"],
            interfaces=sw_info["interfaces"],
        )
        print(
            f"  {sw_name}: pid={mgr._pids.get(sw_name)}, "
            f"thrift={sw_info['thrift_port']}, "
            f"device_id={sw_info['device_id']}"
        )

    # ------------------------------------------------------------------
    # 5.  Wait for all Thrift servers
    # ------------------------------------------------------------------

    print("Waiting for Thrift servers ...")
    for sw_name, sw_info in topo["switches"].items():
        mgr.wait_thrift(sw_info["thrift_port"])
        print(f"  {sw_name}: Thrift ready on port {sw_info['thrift_port']}")

    # ------------------------------------------------------------------
    # 6.  Configure all switches
    # ------------------------------------------------------------------

    print("Configuring switches ...")
    routes = _build_routes(topo, topology_name)

    # Switch IDs from config (default.yaml topology.switch_ids)
    topo_switch_ids = config.get("topology", {}).get("switch_ids", {})

    for sw_name, sw_info in topo["switches"].items():
        thrift = sw_info["thrift_port"]
        # Use config switch_id if available, else fall back to device_id
        config_switch_id = topo_switch_ids.get(sw_name, sw_info["device_id"])
        sw_routes = routes.get(sw_name, [])

        mgr.configure_switch(thrift, config_switch_id, scheme_mode, sw_routes)

        route_desc = ", ".join(
            f"{r['dst_ip']}->port{r['port']}" for r in sw_routes
        )
        print(
            f"  {sw_name}: switch_id={config_switch_id} "
            f"scheme={scheme} routes=[{route_desc}]"
        )

    # ------------------------------------------------------------------
    # 7.  Set queue depth on all ports; rate on bottleneck egress
    # ------------------------------------------------------------------

    print("Configuring queues ...")
    q_cfg = config.get("queue", {})
    queue_depth = q_cfg.get("capacity_packets", 128)
    bottleneck_sw = topo["bottleneck"]["switch"]
    bottleneck_port = topo["bottleneck"]["port"]

    for sw_name, sw_info in topo["switches"].items():
        thrift = sw_info["thrift_port"]
        for port_idx, _veth in sw_info["interfaces"]:
            is_bottleneck = (
                sw_name == bottleneck_sw and port_idx == bottleneck_port
            )
            rate = bottleneck_rate_pps if is_bottleneck else 0
            mgr.set_queue(thrift, port_idx, queue_depth, rate)

    print(
        f"  Bottleneck: {bottleneck_sw} port {bottleneck_port} "
        f"@ {bottleneck_rate_pps} pps, depth={queue_depth}"
    )

    # ------------------------------------------------------------------
    # 8.  Generate traffic plan
    # ------------------------------------------------------------------

    print(f"Generating traffic plan: workload={workload} seed={seed} ...")

    # Inject bottleneck rate into config for workload generators
    run_config = dict(config)
    run_config["bottleneck_rate_pps"] = bottleneck_rate_pps

    plan = generate_traffic_plan(workload, seed, topo, run_config)
    print(
        f"  Plan: {len(plan)} packets, "
        f"sources={sorted({e.src_host for e in plan})}"
    )

    # ------------------------------------------------------------------
    # 9.  Start tcpdump on all host interfaces
    # ------------------------------------------------------------------

    print("Starting packet capture ...")
    tcpdump_procs: list[tuple[str, subprocess.Popen, Path]] = []
    for host_name, host_info in topo["hosts"].items():
        ns = host_info["ns"]
        iface = host_info["iface"]
        pcap_path = run_tmp / f"capture_{host_name}.pcap"
        proc = subprocess.Popen(
            [
                "ip", "netns", "exec", ns,
                "tcpdump", "-i", iface,
                "-w", str(pcap_path),
                "-U",
                "udp",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        tcpdump_procs.append((host_name, proc, pcap_path))
        print(f"  {host_name}: tcpdump on {iface} (ns={ns})")

    time.sleep(0.5)  # Let tcpdump processes initialize

    # ------------------------------------------------------------------
    # 10-11.  Execute traffic (synchronized), wait for drain
    # ------------------------------------------------------------------

    print(f"Running traffic: duration={duration_s}s ...")

    traffic_dir = str(run_tmp / "traffic_logs")
    os.makedirs(traffic_dir, exist_ok=True)

    exec_result = execute_traffic_plan(plan, topo, traffic_dir)
    t0_ns = exec_result["t0_ns"]

    # Compute actual rates using the measured sender timestamps
    rates = compute_actual_rates(exec_result, duration_s)
    sender_total = rates.get("total_packets_sent", 0)

    print(f"  T0={t0_ns} ns")
    print(f"  Packets sent: {sender_total}")
    print(f"  Sender rate: {rates['sender_rate_pps']:.1f} pps")

    # Drain period
    actual_drain = max(drain_s, duration_s * 0.1)
    print(f"  Draining for {actual_drain:.1f}s ...")
    time.sleep(actual_drain)

    # ------------------------------------------------------------------
    # 12.  Stop tcpdump and collect pcaps
    # ------------------------------------------------------------------

    print("Stopping packet capture ...")
    for host_name, proc, pcap_path in tcpdump_procs:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass
        except OSError:
            pass
        print(
            f"  {host_name}: tcpdump stopped "
            f"({pcap_path.stat().st_size} bytes)"
        )

    # Merge pcaps: collect all non-empty captures
    merged_pcap = output_dir / "capture.pcap"
    all_pcaps = sorted(
        [
            p for _, _, p in tcpdump_procs
            if p.exists() and p.stat().st_size > 0
        ],
        key=lambda p: p.stat().st_size,
        reverse=True,
    )
    if all_pcaps:
        # Use the largest pcap as the primary merged capture
        shutil.copy2(all_pcaps[0], merged_pcap)
        # If there are multiple non-empty pcaps, try to merge with mergecap
        if len(all_pcaps) > 1:
            try:
                merge_result = subprocess.run(
                    ["mergecap", "-w", str(merged_pcap)]
                    + [str(p) for p in all_pcaps],
                    capture_output=True, text=True, timeout=30,
                )
                if merge_result.returncode == 0:
                    print(f"  Merged {len(all_pcaps)} pcaps -> {merged_pcap}")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                # mergecap not available; keep the largest single pcap
                pass
    else:
        print("  WARNING: no non-empty pcaps captured", file=sys.stderr)

    # ------------------------------------------------------------------
    # 13.  Collect switch logs
    # ------------------------------------------------------------------

    print("Collecting switch logs ...")
    oracle_csv = output_dir / "oracle.csv"
    oracle_entries = 0

    for sw_name in topo["switches"]:
        log_path = mgr.get_log_path(sw_name)
        if log_path and os.path.exists(log_path):
            dest = output_dir / f"switch_{sw_name}.log"
            shutil.copy2(log_path, dest)
            entries = parse_bmv2_log(
                log_path=str(dest),
                output_path=str(oracle_csv),
                run_id=run_id,
                scheme=scheme,
                seed=seed,
            )
            oracle_entries += entries
            print(f"  {sw_name}: {entries} oracle entries")
        else:
            print(f"  WARNING: no log for switch {sw_name}", file=sys.stderr)

    # ------------------------------------------------------------------
    # 14.  Read Gate B sampling counters from bottleneck ports
    # ------------------------------------------------------------------

    print("Reading Gate B sampling counters ...")
    gate_b_counters: dict[str, dict] = {}
    bottleneck_sw_info = topo["switches"][bottleneck_sw]
    bottleneck_thrift = bottleneck_sw_info["thrift_port"]

    gate_b_counters[bottleneck_sw] = mgr.read_sampling_counters(
        bottleneck_thrift, bottleneck_port
    )
    for key, val in gate_b_counters[bottleneck_sw].items():
        print(f"  {bottleneck_sw} port {bottleneck_port} {key}: {val}")

    # Also read counters from non-bottleneck ports for completeness
    for sw_name, sw_info in topo["switches"].items():
        if sw_name == bottleneck_sw:
            continue
        thrift = sw_info["thrift_port"]
        gate_b_counters[sw_name] = {}
        for port_idx, _veth in sw_info["interfaces"]:
            gate_b_counters[sw_name][f"port_{port_idx}"] = (
                mgr.read_sampling_counters(thrift, port_idx)
            )

    # ------------------------------------------------------------------
    # 15.  Stop topology (teardown everything)
    # ------------------------------------------------------------------

    print("Tearing down topology ...")
    mgr.stop_all()

    # ------------------------------------------------------------------
    # 16.  Post-processing
    # ------------------------------------------------------------------

    print("Post-processing ...")

    # 16a. Parse pcap -> telemetry CSV
    telemetry_csv = output_dir / "telemetry_samples.csv"
    total_pcap_packets = 0
    telemetry_pcap_packets = 0
    if merged_pcap.exists() and merged_pcap.stat().st_size > 0:
        total_pcap_packets, telemetry_pcap_packets = parse_pcap_to_csv(
            pcap_path=str(merged_pcap),
            output_path=str(telemetry_csv),
            run_id=run_id,
            scheme=scheme,
            seed=seed,
            int_port=int_port,
        )
    else:
        print(
            "  WARNING: no pcap captured, creating empty telemetry CSV",
            file=sys.stderr,
        )
        telemetry_csv.write_text(
            "run_id,scheme,seed,recv_ts,src_ip,dst_ip,packet_num,"
            "switch_id,egress_port,state,reason,qdepth,q_pred_far,"
            "hop_ts_us,hop_index,total_hops,shim_magic,original_dport\n"
        )

    # 16b. Oracle CSV header (ensure it exists even when empty)
    if oracle_entries == 0:
        from oracle.parse_bmv2_log import ORACLE_CSV_HEADER
        oracle_csv.write_text(",".join(ORACLE_CSV_HEADER) + "\n")

    # 16c. Detect events
    events_csv = output_dir / "events.csv"
    if oracle_csv.exists() and oracle_entries > 0:
        events = detect_events(
            oracle_csv=str(oracle_csv),
            q_event=config["queue"]["event_threshold_packets"],
            q_release=config["queue"]["release_threshold_packets"],
        )
        write_events_csv(events, str(events_csv), run_id, scheme, seed)
        print(f"  Events detected: {len(events)}")
    else:
        from oracle.events import EVENTS_CSV_HEADER
        events_csv.write_text(",".join(EVENTS_CSV_HEADER) + "\n")

    # 16d. Compute metrics
    try:
        from analysis.metrics import compute_all_metrics
        metrics = compute_all_metrics(
            oracle_csv=str(oracle_csv),
            telemetry_csv=str(telemetry_csv),
            events_csv=str(events_csv),
            config=config,
        )
        with open(output_dir / "metrics.json", "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"  Metrics computed: {len(metrics)} categories")
    except ImportError as e:
        print(
            f"  WARNING: analysis.metrics not available ({e})",
            file=sys.stderr,
        )
    except Exception as e:
        print(
            f"  WARNING: metrics computation failed: {e}",
            file=sys.stderr,
        )

    # 16e. Compute actual rates JSON
    with open(output_dir / "actual_rates.json", "w") as f:
        json.dump(rates, f, indent=2)
    print(f"  Actual rates: {json.dumps(rates)}")

    # 16f. Save sender logs
    for log_file in Path(traffic_dir).glob("*_sender_log.csv"):
        shutil.copy2(log_file, output_dir / log_file.name)
    n_sender_logs = len(list(Path(traffic_dir).glob("*_sender_log.csv")))
    print(f"  Sender logs copied: {n_sender_logs}")

    # ------------------------------------------------------------------
    # 17.  Save manifest (final, with runtime metadata)
    # ------------------------------------------------------------------

    manifest = create_manifest(
        config=config,
        run_id=run_id,
        scheme=scheme,
        seed=seed,
        topology=topology_name,
        extras={
            "duration_s": duration_s,
            "bottleneck_rate_pps": bottleneck_rate_pps,
            "packet_size": packet_size,
            "workload": workload,
            "int_port": int_port,
            "warmup_s": warmup_s,
            "drain_s": actual_drain,
            "sender_total_packets": sender_total,
            "oracle_entries": oracle_entries,
            "pcap_total_packets": total_pcap_packets,
            "pcap_telemetry_packets": telemetry_pcap_packets,
        },
    )
    save_manifest(manifest, str(output_dir))

    # ------------------------------------------------------------------
    # 18.  Save config_resolved.yaml
    # ------------------------------------------------------------------

    with open(output_dir / "config_resolved.yaml", "w") as f:
        yaml.dump(config, f)

    # ------------------------------------------------------------------
    # 19.  Save gate_b_counters.json
    # ------------------------------------------------------------------

    with open(output_dir / "gate_b_counters.json", "w") as f:
        json.dump(gate_b_counters, f, indent=2)

    # ------------------------------------------------------------------
    # 20.  Sanity checks
    # ------------------------------------------------------------------

    print("Running sanity checks ...")
    _sanity_checks(
        output_dir=output_dir,
        topo=topo,
        scheme=scheme,
        oracle_entries=oracle_entries,
        manifest=manifest,
        sender_total=sender_total,
        pcap_path=merged_pcap,
    )

    # ------------------------------------------------------------------
    # 21.  Cleanup temp directory
    # ------------------------------------------------------------------

    try:
        shutil.rmtree(run_tmp, ignore_errors=True)
    except Exception:
        pass

    print(f"=== Experiment complete: {output_dir} ===")
    return str(output_dir)


# ===========================================================================
# CLI
# ===========================================================================


def main() -> None:
    """Command-line entry point for ``experiments/run_one.py``."""
    parser = argparse.ArgumentParser(
        description="Run a single PTT-INT experiment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scheme", default="PTT",
        choices=list(SCHEME_MAP.keys()),
        help="Telemetry scheme (default: PTT)",
    )
    parser.add_argument(
        "--seed", type=int, default=1,
        help="Experiment PRNG seed (default: 1)",
    )
    parser.add_argument(
        "--workload", default="ramp_medium",
        help="Workload name from WORKLOAD_REGISTRY (default: ramp_medium)",
    )
    parser.add_argument(
        "--topology", default="single_bottleneck",
        choices=["single_bottleneck", "incast", "leaf_spine"],
        help="Topology name (default: single_bottleneck)",
    )
    parser.add_argument(
        "--duration", type=float, default=30.0,
        help="Experiment duration in seconds (default: 30)",
    )
    parser.add_argument(
        "--bottleneck-rate-pps", type=int, default=100,
        help="Bottleneck service rate in packets/sec (default: 100)",
    )
    parser.add_argument(
        "--packet-size", type=int, default=1000,
        help="UDP payload size in bytes (default: 1000)",
    )
    parser.add_argument(
        "--output-dir", default=None,
        help="Output directory (auto-generated under results/raw/ if not set)",
    )
    parser.add_argument(
        "--warmup", type=float, default=2.0,
        help="Warmup duration before traffic (seconds, default: 2.0)",
    )
    parser.add_argument(
        "--drain", type=float, default=2.0,
        help="Drain period after traffic completes (seconds, default: 2.0)",
    )
    parser.add_argument(
        "--config", default=None,
        help="Config file path (default: config/default.yaml)",
    )
    parser.add_argument(
        "--tmpdir", default=None,
        help="Temporary directory for switch artifacts",
    )
    parser.add_argument(
        "--int-port", type=int, default=32768,
        help="INT UDP destination port (default: 32768)",
    )
    args = parser.parse_args()

    # Load config
    cfg = load_config(args.config)

    # Run experiment
    output = run_experiment(
        scheme=args.scheme,
        seed=args.seed,
        workload=args.workload,
        topology_name=args.topology,
        duration_s=args.duration,
        output_dir=args.output_dir,
        config=cfg,
        bottleneck_rate_pps=args.bottleneck_rate_pps,
        packet_size=args.packet_size,
        int_port=args.int_port,
        warmup_s=args.warmup,
        drain_s=args.drain,
        tmpdir=args.tmpdir,
    )
    print(f"Output: {output}")


if __name__ == "__main__":
    main()
