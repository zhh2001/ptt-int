#!/usr/bin/env python3
"""Gate A: Queue Calibration.

Runs stable workloads at 5 load ratios through single_bottleneck topology,
extracts oracle queue depth data, computes trend statistics, and produces
queue_calibration.csv + queue_calibration.png.
"""

import sys, os, csv, json, argparse, tempfile, time, shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from experiments.switch_manager import SwitchManager
from experiments.traffic_generator import generate_traffic_plan, execute_traffic_plan
from experiments.workloads import generate_workload
from oracle.parse_bmv2_log import parse_bmv2_log

Q_CAP = 128
Q_EVENT = 96
LOAD_RATIOS = [0.50, 0.80, 0.95, 1.05, 1.20]


def _build_routes(topo):
    """Build bidirectional LPM routes for single_bottleneck topology."""
    hosts = topo["hosts"]
    h1_ip = hosts["h1"]["ip"].split("/")[0]
    h2_ip = hosts["h2"]["ip"].split("/")[0]
    return {
        "s1": [{"dst_ip": f"{h1_ip}/32", "port": 0}, {"dst_ip": f"{h2_ip}/32", "port": 1}],
        "s2": [{"dst_ip": f"{h1_ip}/32", "port": 0}, {"dst_ip": f"{h2_ip}/32", "port": 1}],
    }


def compute_trend_stats(timestamps_s, q_values):
    n = len(q_values)
    if n < 2:
        return {"slope": 0.0, "r_squared": 0.0, "median": 0.0, "p95": 0.0,
                "p99": 0.0, "peak": 0.0, "threshold_crossings": 0, "n": n}
    mean_t = sum(timestamps_s) / n
    mean_q = sum(q_values) / n
    cov = sum((timestamps_s[i] - mean_t) * (q_values[i] - mean_q) for i in range(n))
    var_t = sum((t - mean_t) ** 2 for t in timestamps_s)
    slope = cov / var_t if var_t > 0 else 0.0
    intercept = mean_q - slope * mean_t
    ss_res = sum((q_values[i] - (slope * timestamps_s[i] + intercept)) ** 2 for i in range(n))
    ss_tot = sum((q - mean_q) ** 2 for q in q_values)
    r_squared = 1.0 - ss_res / ss_tot if ss_tot > 0 else 0.0
    sorted_q = sorted(q_values)
    median = sorted_q[n // 2]
    p95 = sorted_q[min(int(n * 0.95), n - 1)]
    p99 = sorted_q[min(int(n * 0.99), n - 1)]
    peak = max(q_values)
    threshold_crossings = sum(1 for q in q_values if q >= Q_EVENT)
    return {"slope": round(slope, 4), "r_squared": round(r_squared, 4),
            "median": median, "p95": p95, "p99": p99, "peak": peak,
            "threshold_crossings": threshold_crossings, "n": n}


def run_calibration(output_dir, bottleneck_rate_pps=100, duration_s=15, warmup_s=3):
    p4_json = str(REPO_ROOT / "p4src" / "ptt_int.json")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    results = {}
    all_series = {}

    for ratio in LOAD_RATIOS:
        label = f"{ratio:.2f}C"
        target_pps = int(bottleneck_rate_pps * ratio)
        print(f"\n--- Calibration: {label} ({target_pps} pps) ---")

        tmpdir = tempfile.mkdtemp(prefix="ptt_calib_")
        try:
            mgr = SwitchManager(tmpdir=str(tmpdir), p4_json_path=p4_json)
            topo = mgr.create_single_bottleneck()

            # Start switches
            for sn, si in topo["switches"].items():
                mgr.start_switch(sn, si["thrift_port"], si["device_id"], si["interfaces"])
                mgr.wait_thrift(si["thrift_port"])

            # Configure
            routes = _build_routes(topo)
            for sn, si in topo["switches"].items():
                mgr.configure_switch(si["thrift_port"], si["device_id"], 0, routes.get(sn, []))

            # Set queues
            bn_sw = topo["bottleneck"]["switch"]
            bn_port = topo["bottleneck"]["port"]
            for sn, si in topo["switches"].items():
                for pi, _ in si["interfaces"]:
                    rate = bottleneck_rate_pps if (sn == bn_sw and pi == bn_port) else 0
                    mgr.set_queue(si["thrift_port"], pi, Q_CAP, rate)

            # Generate traffic plan: stable at target load
            config = {
                "bottleneck_rate_pps": bottleneck_rate_pps,
                "packet": {"original_packet_size": 1000},
            }
            runtime = {
                "bottleneck_rate_pps": bottleneck_rate_pps,
                "duration_s": duration_s + warmup_s,
            }

            plan = generate_workload("stable", 42, topo, config)
            # Filter to target rate: regenerate with exact params
            from experiments.workloads import generate_stable
            plan = generate_stable(seed=42, topology=topo, config=config,
                                   load_ratio=ratio, duration_s=duration_s + warmup_s,
                                   runtime=runtime)

            # Start tcpdump on receiver
            import subprocess as sp
            h2_ns = topo["hosts"]["h2"]["ns"]
            h2_iface = topo["hosts"]["h2"]["iface"]
            pcap_path = os.path.join(tmpdir, "recv.pcap")
            tcpdump = sp.Popen(["ip", "netns", "exec", h2_ns, "tcpdump",
                                "-i", h2_iface, "-w", pcap_path, "-U"],
                               stdout=sp.DEVNULL, stderr=sp.DEVNULL)
            time.sleep(0.5)

            # Execute traffic
            traffic_dir = os.path.join(tmpdir, "traffic")
            os.makedirs(traffic_dir, exist_ok=True)
            exec_result = execute_traffic_plan(plan, topo, traffic_dir)

            # Drain
            time.sleep(2)
            tcpdump.terminate()
            tcpdump.wait(timeout=5)

            # Count received packets (UDP only, filter out ARP/ICMP noise)
            received = 0
            try:
                r = sp.run(["tcpdump", "-r", pcap_path, "-nn", "udp"],
                           capture_output=True, text=True, timeout=10)
                received = len([l for l in r.stdout.splitlines() if l.strip()])
            except Exception:
                pass

            # Collect oracle data from bottleneck switch only (s2, port 1)
            oracle_rows = []
            bn_sw = topo["bottleneck"]["switch"]
            log_path = mgr.get_log_path(bn_sw)
            if log_path and os.path.exists(log_path):
                out_csv = os.path.join(tmpdir, f"oracle_{bn_sw}.csv")
                parse_bmv2_log(log_path=log_path, output_path=out_csv,
                               run_id=f"calib_{label}", scheme="FULL", seed=42)
                if os.path.exists(out_csv):
                    with open(out_csv) as f:
                        for row in csv.DictReader(f):
                            # Only use bottleneck port entries
                            if int(row.get("port", -1)) == bn_port:
                                oracle_rows.append(row)

            # Extract queue time series relative to first oracle timestamp
            # (oracle timestamps are switch-internal microseconds, but relative
            #  deltas are correct for trend analysis)
            timestamps_s, q_values = [], []
            if oracle_rows:
                t0_us = int(oracle_rows[0]["ts_us"])
                for row in oracle_rows:
                    try:
                        ts_s = (int(row["ts_us"]) - t0_us) / 1_000_000.0
                        q = int(row.get("q", 0))
                        timestamps_s.append(ts_s)
                        q_values.append(q)
                    except (ValueError, KeyError):
                        continue

            stats = compute_trend_stats(timestamps_s, q_values)

            # --- Compute actual TX rate from sender_log.csv timestamps ---
            # Use the actual_time_ns field within the measurement window
            # (excluding warmup) for a scientifically rigorous rate measurement.
            sender_count = 0
            total_sent = 0
            tx_rate_pps = 0.0
            try:
                sender_log = os.path.join(tmpdir, "traffic", "h1_sender_log.csv")
                with open(sender_log) as f:
                    sender_rows = list(csv.DictReader(f))
                total_sent = len(sender_rows)
                # Convert actual_time_ns to seconds since first packet
                t0_ns = int(sender_rows[0]["actual_time_ns"]) if sender_rows else 0
                tx_ts_in_window = []
                for r in sender_rows:
                    t_s = (int(r["actual_time_ns"]) - t0_ns) / 1e9
                    if warmup_s <= t_s <= warmup_s + duration_s:
                        tx_ts_in_window.append(t_s)
                sender_count = len(tx_ts_in_window)
                if len(tx_ts_in_window) >= 2:
                    span = tx_ts_in_window[-1] - tx_ts_in_window[0]
                    tx_rate_pps = sender_count / span if span > 0 else 0.0
            except Exception:
                total_sent = sum(r["count"] for r in exec_result.get("sender_results", {}).values())
                sender_count = total_sent
                tx_rate_pps = sender_count / duration_s if duration_s > 0 else 0.0

            # --- Compute actual RX rate from pcap timestamps (UDP only) ---
            rx_rate_pps = 0.0
            total_received = 0
            received = 0
            try:
                import re as _re
                r = sp.run(["tcpdump", "-r", pcap_path, "-tt", "-nn", "udp"],
                           capture_output=True, text=True, timeout=10)
                ts_pat = _re.compile(r"^(\d+\.\d+)")
                rx_ts_all = []
                for line in r.stdout.splitlines():
                    m = ts_pat.match(line.strip())
                    if m:
                        rx_ts_all.append(float(m.group(1)))
                total_received = len(rx_ts_all)
                # Filter to measurement window: exclude first warmup_s seconds
                # (pcap timestamps are Unix epoch — use relative offset from first pkt)
                if rx_ts_all:
                    rx_t0 = rx_ts_all[0]
                    rx_ts_in_window = []
                    for ts in rx_ts_all:
                        t_rel = ts - rx_t0
                        if warmup_s - 0.5 <= t_rel <= warmup_s + duration_s + 0.5:
                            rx_ts_in_window.append(ts)
                    received = len(rx_ts_in_window)
                    if len(rx_ts_in_window) >= 2:
                        span = rx_ts_in_window[-1] - rx_ts_in_window[0]
                        rx_rate_pps = received / span if span > 0.01 else 0.0
            except Exception:
                pass

            packet_loss = total_sent - total_received if total_sent > 0 else 0

            # Checks
            checks = []
            if ratio <= 0.95:
                checks += [
                    {"check": "median_below_20", "passed": stats["median"] < 20,
                     "detail": f"median={stats['median']}"},
                    {"check": "no_sustained_buildup", "passed": stats["slope"] < 0.5,
                     "detail": f"slope={stats['slope']:.2f}"},
                    {"check": "p95_below_half_event", "passed": stats["p95"] < Q_EVENT / 2,
                     "detail": f"p95={stats['p95']}"},
                ]
            else:
                checks += [
                    {"check": "positive_buildup", "passed": stats["slope"] > 0.5,
                     "detail": f"slope={stats['slope']:.2f}"},
                ]
                if ratio >= 1.20:
                    checks.append({"check": "crosses_q_event",
                                   "passed": stats["threshold_crossings"] > 0,
                                   "detail": f"crossings={stats['threshold_crossings']}"})
            checks.append({"check": "no_capacity_violation", "passed": stats["peak"] <= Q_CAP,
                           "detail": f"peak={stats['peak']}"})

            all_pass = all(c["passed"] for c in checks)
            results[label] = {"load_ratio": ratio, "target_rate_pps": target_pps,
                              "tx_rate_pps": round(tx_rate_pps, 1),
                              "rx_rate_pps": round(rx_rate_pps, 1),
                              "stats": stats, "checks": checks, "all_pass": all_pass,
                              "packets_sent": sender_count, "packets_received": received,
                              "packet_loss": packet_loss}
            all_series[label] = {"timestamps_s": timestamps_s, "q_values": q_values}

            status = "PASS" if all_pass else "FAIL"
            print(f"  {label}: {status} tx_rate={tx_rate_pps:.1f} pps rx_rate={rx_rate_pps:.1f} pps "
                  f"sent={sender_count} recv={received} loss={packet_loss} "
                  f"median={stats['median']} peak={stats['peak']} "
                  f"p95={stats['p95']} p99={stats['p99']} "
                  f"slope={stats['slope']:.2f} xings={stats['threshold_crossings']} n={stats['n']}")

            mgr.stop_all()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # Save CSV
    csv_path = output_dir / "queue_calibration.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["load_ratio", "target_rate_pps", "tx_rate_pps", "rx_rate_pps",
                         "packets_sent", "packets_received", "packet_loss",
                         "median", "p95", "p99", "peak", "slope", "r_squared",
                         "threshold_crossings", "n_samples", "all_checks_pass"])
        for label, r in results.items():
            s = r["stats"]
            writer.writerow([r["load_ratio"], r["target_rate_pps"],
                             r["tx_rate_pps"], r["rx_rate_pps"],
                             r["packets_sent"], r["packets_received"],
                             r["packet_loss"],
                             s["median"], s["p95"],
                             s["p99"], s["peak"], s["slope"], s["r_squared"],
                             s["threshold_crossings"], s["n"], r["all_pass"]])

    # Generate plot
    try:
        _plot_calibration(all_series, output_dir / "queue_calibration.png")
    except Exception as e:
        print(f"  WARNING: Plot generation failed: {e}")

    overall = all(r["all_pass"] for r in results.values())
    print(f"\n=== Gate A Calibration: {'PASS' if overall else 'FAIL'} ===")
    return results


def _plot_calibration(all_series, output_path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(10, 6))
    colors = ["blue", "green", "orange", "red", "darkred"]

    for (label, series), color in zip(all_series.items(), colors):
        ts = series["timestamps_s"]
        qs = series["q_values"]
        if ts and qs:
            ax.plot(ts, qs, color=color, alpha=0.5, linewidth=0.5, label=f"{label} (raw)")
            # Moving average
            window = max(1, len(qs) // 50)
            if window > 1:
                ma = [sum(qs[max(0,i-window):i+1])/min(i+1,window) for i in range(len(qs))]
                ax.plot(ts, ma, color=color, linewidth=1.5, label=f"{label} (MA)")

    ax.axhline(y=96, color="red", linestyle="--", alpha=0.7, label="Q_EVENT=96")
    ax.axhline(y=64, color="orange", linestyle="--", alpha=0.7, label="Q_RELEASE=64")
    ax.axhline(y=128, color="black", linestyle=":", alpha=0.5, label="Q_CAP=128")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Queue Depth (packets)")
    ax.set_title("Gate A: Queue Calibration")
    ax.legend(fontsize=7, loc="upper left")
    ax.grid(True, alpha=0.3)
    ax.set_ylim(-5, 140)
    fig.tight_layout()
    fig.savefig(str(output_path), dpi=150)
    plt.close(fig)
    print(f"  Plot saved: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Gate A: Queue Calibration")
    parser.add_argument("--output-dir", default="results/calibration")
    parser.add_argument("--bottleneck-rate-pps", type=int, default=100)
    parser.add_argument("--duration", type=int, default=15)
    parser.add_argument("--warmup", type=int, default=3)
    args = parser.parse_args()
    run_calibration(args.output_dir, args.bottleneck_rate_pps,
                    args.duration, args.warmup)


if __name__ == "__main__":
    main()
