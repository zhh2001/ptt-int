#!/usr/bin/env python3
"""PTT-INT core metrics computation.

Computes all required metrics from raw data (oracle.csv, telemetry_samples.csv, events.csv). No fabricated data.
"""

import csv
import json
import sys
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


# --- Helper Functions ---

def read_oracle(oracle_csv: str) -> list[dict]:
    """Read oracle CSV into list of dicts with typed values."""
    rows = []
    with open(oracle_csv) as f:
        for row in csv.DictReader(f):
            row["q"] = int(row["q"])
            row["ts_us"] = int(row["ts_us"])
            row["state"] = int(row["state"])
            row["target"] = int(row["target"])
            row["trend"] = int(row["trend"])
            row["q_pred_near"] = int(row["q_pred_near"])
            row["q_pred_far"] = int(row["q_pred_far"])
            row["switch_id"] = int(row["switch_id"])
            row["port"] = int(row["port"])
            rows.append(row)
    return rows


def read_telemetry(telemetry_csv: str) -> list[dict]:
    """Read telemetry samples CSV."""
    rows = []
    try:
        with open(telemetry_csv) as f:
            for row in csv.DictReader(f):
                row["qdepth"] = int(row["qdepth"])
                row["q_pred_far"] = int(row.get("q_pred_far", 0))
                row["hop_ts_us"] = int(row.get("hop_ts_us", 0))
                row["switch_id"] = int(row.get("switch_id", 0))
                row["egress_port"] = int(row.get("egress_port", 0))
                row["hop_index"] = int(row.get("hop_index", 0))
                row["total_hops"] = int(row.get("total_hops", 0))
                rows.append(row)
    except FileNotFoundError:
        pass
    return rows


def read_events(events_csv: str) -> list[dict]:
    """Read events CSV."""
    rows = []
    try:
        with open(events_csv) as f:
            for row in csv.DictReader(f):
                row["start_ts_us"] = int(row["start_ts_us"])
                row["end_ts_us"] = int(row["end_ts_us"])
                row["peak_q"] = int(row["peak_q"])
                row["switch_id"] = int(row["switch_id"])
                row["port"] = int(row["port"])
                row["duration_us"] = int(row["duration_us"])
                rows.append(row)
    except FileNotFoundError:
        pass
    return rows


# --- Metric Functions ---

def compute_lead_times(
    oracle: list[dict],
    telemetry: list[dict],
    events: list[dict],
) -> dict:
    """Compute burst and watch lead times per event.

    Lead time = t_event - t_BURST (positive = ahead of event).
    """
    result = {
        "burst_lead_times": [],
        "watch_lead_times": [],
        "median_burst_lead_us": 0.0,
        "median_watch_lead_us": 0.0,
        "positive_burst_ratio": 0.0,
        "positive_watch_ratio": 0.0,
    }

    if not events or not telemetry:
        return result

    for evt in events:
        event_start = evt["start_ts_us"]
        event_sw = evt["switch_id"]
        event_port = evt["port"]

        burst_ts = None
        watch_ts = None

        # Find first BURST and WATCH telemetry samples before event
        for ts in telemetry:
            if ts["switch_id"] != event_sw or ts["egress_port"] != event_port:
                continue
            t = ts["hop_ts_us"]
            state = ts.get("state", "")
            if t > event_start:
                break
            if state == "BURST" and burst_ts is None:
                burst_ts = t
            if state == "WATCH" and watch_ts is None:
                watch_ts = t

        if burst_ts is not None:
            lead = event_start - burst_ts
            result["burst_lead_times"].append(lead)

        if watch_ts is not None:
            lead = event_start - watch_ts
            result["watch_lead_times"].append(lead)

    if result["burst_lead_times"]:
        sorted_bl = sorted(result["burst_lead_times"])
        n = len(sorted_bl)
        result["median_burst_lead_us"] = sorted_bl[n // 2]
        result["positive_burst_ratio"] = (
            sum(1 for l in result["burst_lead_times"] if l > 0) / n
        )

    if result["watch_lead_times"]:
        sorted_wl = sorted(result["watch_lead_times"])
        n = len(sorted_wl)
        result["median_watch_lead_us"] = sorted_wl[n // 2]
        result["positive_watch_ratio"] = (
            sum(1 for l in result["watch_lead_times"] if l > 0) / n
        )

    return result


def compute_predictive_precision_recall(
    oracle: list[dict],
    events: list[dict],
    q_event: int = 96,
    near_horizon: int = 2,
    epoch_us: int = 5000,
) -> dict:
    """Compute predictive precision, recall, and F1.

    A predictive BURST entry is TP if:
      - q < Q_EVENT at entry time
      - Event occurs within T_valid = H_N * W + W
    """
    T_valid = near_horizon * epoch_us + epoch_us  # default: 2*5000 + 5000 = 15000 us

    # Collect all predictive BURST entries from oracle
    # A predictive entry is when target=BURST but q < Q_EVENT
    predictive_entries = []
    for row in oracle:
        if row["target"] == 2 and row["q"] < q_event:
            predictive_entries.append({
                "ts_us": row["ts_us"],
                "switch_id": row["switch_id"],
                "port": row["port"],
            })

    tp = 0
    fp = 0

    for pe in predictive_entries:
        # Check if any event from this port starts within T_valid
        matched = False
        for evt in events:
            if evt["switch_id"] != pe["switch_id"] or evt["port"] != pe["port"]:
                continue
            if pe["ts_us"] < evt["start_ts_us"] <= pe["ts_us"] + T_valid:
                matched = True
                break
            # Also consider: event already started but pe is within it
            if evt["start_ts_us"] <= pe["ts_us"] <= evt["end_ts_us"]:
                matched = True
                break

        if matched:
            tp += 1
        else:
            fp += 1

    # FN = events that had NO predictive BURST within T_valid before them
    fn = 0
    for evt in events:
        has_predictive = False
        for pe in predictive_entries:
            if pe["switch_id"] != evt["switch_id"] or pe["port"] != evt["port"]:
                continue
            if evt["start_ts_us"] - T_valid <= pe["ts_us"] <= evt["start_ts_us"]:
                has_predictive = True
                break
        if not has_predictive:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "T_valid_us": T_valid,
    }


def compute_early_coverage(
    events: list[dict],
    burst_lead_times: list[int],
) -> float:
    """Compute early-event coverage.

    Fraction of events with positive burst lead time.
    """
    if not events:
        return 0.0
    positive_count = sum(1 for lt in burst_lead_times if lt > 0)
    return positive_count / len(events) if events else 0.0


def compute_telemetry_overhead(
    telemetry: list[dict],
    total_packets: int = 0,
    original_packet_size: int = 1000,
    shim_bytes: int = 8,
    hop_record_bytes: int = 12,
) -> dict:
    """Compute telemetry byte overhead, instrumented ratio, hop rate."""
    instrumented_packets = set()
    total_hop_records = 0
    total_telemetry_bytes = 0

    for row in telemetry:
        pkt_id = row.get("packet_num", 0)
        hops = row.get("total_hops", 0)
        instrumented_packets.add(pkt_id)
        total_hop_records += 1

        # First insertion: 8B shim + N*12B hops
        # All packets in telemetry CSV are instrumented
        pkt_bytes = shim_bytes + hops * hop_record_bytes
        total_telemetry_bytes += pkt_bytes

    n_instrumented = len(instrumented_packets)
    n_all = max(total_packets, n_instrumented)

    byte_overhead = (
        total_telemetry_bytes / (n_all * original_packet_size)
        if n_all > 0 else 0.0
    )

    instrumented_ratio = n_instrumented / n_all if n_all > 0 else 0.0

    return {
        "telemetry_bytes": total_telemetry_bytes,
        "original_bytes_est": n_all * original_packet_size,
        "byte_overhead_ratio": byte_overhead,
        "instrumented_packets": n_instrumented,
        "total_packets": n_all,
        "instrumented_ratio": instrumented_ratio,
        "hop_records": total_hop_records,
    }


def compute_state_occupancy(oracle: list[dict]) -> dict:
    """Compute state occupancy: fraction of time in QUIET/WATCH/BURST."""
    if not oracle:
        return {"P_QUIET": 1.0, "P_WATCH": 0.0, "P_BURST": 0.0, "total_epochs": 0}

    counts = {0: 0, 1: 0, 2: 0}
    for row in oracle:
        s = row["state"]
        if s in counts:
            counts[s] += 1

    total = sum(counts.values())
    if total == 0:
        return {"P_QUIET": 1.0, "P_WATCH": 0.0, "P_BURST": 0.0, "total_epochs": 0}

    return {
        "P_QUIET": counts[0] / total,
        "P_WATCH": counts[1] / total,
        "P_BURST": counts[2] / total,
        "total_epochs": total,
    }


def compute_nmae(
    oracle: list[dict],
    telemetry: list[dict],
    q_cap: int = 128,
) -> dict:
    """Compute NMAE of reconstructed queue.

    Uses last-sample-hold: q_hat(t) = q(last_report_at_or_before_t).
    """
    if not oracle or not telemetry:
        return {"NMAE": None, "n_samples": 0}

    # Build time series of reported q values per (switch, port)
    reports = defaultdict(list)  # (sw, port) -> [(ts, q), ...]
    for row in telemetry:
        key = (row.get("switch_id", 0), row.get("egress_port", 0))
        reports[key].append((row.get("hop_ts_us", 0), row.get("qdepth", 0)))

    # Sort reports by timestamp
    for key in reports:
        reports[key].sort()

    # For each oracle sample, find last report and compute error
    total_abs_error = 0
    n = 0
    for row in oracle:
        key = (row["switch_id"], row["port"])
        ts = row["ts_us"]
        q_true = row["q"]

        # Find last report at or before ts
        q_hat = None
        rep_list = reports.get(key, [])
        for r_ts, r_q in rep_list:
            if r_ts <= ts:
                q_hat = r_q
            else:
                break

        if q_hat is not None:
            total_abs_error += abs(q_true - q_hat)
            n += 1

    if n == 0:
        return {"NMAE": None, "n_samples": 0}

    nmae = total_abs_error / (n * q_cap)
    return {"NMAE": nmae, "n_samples": n, "total_abs_error": total_abs_error}


def compute_peak_error(
    oracle: list[dict],
    telemetry: list[dict],
) -> dict:
    """Compute peak queue error."""
    if not oracle or not telemetry:
        return {"peak_error": None, "peak_q_true": 0, "peak_q_hat": 0}

    reports = defaultdict(list)
    for row in telemetry:
        key = (row.get("switch_id", 0), row.get("egress_port", 0))
        reports[key].append((row.get("hop_ts_us", 0), row.get("qdepth", 0)))

    for key in reports:
        reports[key].sort()

    max_error = 0
    peak_q_true = 0
    peak_q_hat = 0

    for row in oracle:
        key = (row["switch_id"], row["port"])
        ts = row["ts_us"]
        q_true = row["q"]

        if q_true > peak_q_true:
            peak_q_true = q_true

        q_hat = None
        rep_list = reports.get(key, [])
        for r_ts, r_q in rep_list:
            if r_ts <= ts:
                q_hat = r_q
            else:
                break

        if q_hat is not None:
            error = abs(q_true - q_hat)
            if error > max_error:
                max_error = error
                peak_q_hat = q_hat

    return {
        "peak_error": max_error,
        "peak_q_true": peak_q_true,
        "peak_q_hat": peak_q_hat,
    }


def compute_event_window_density(
    telemetry: list[dict],
    events: list[dict],
    window_us: int = 100000,  # 100ms window around event
) -> dict:
    """Compute event-window sample density."""
    if not events:
        return {"event_window_density_per_ms": 0.0, "background_density_per_ms": 0.0}

    # Determine which timestamps fall in event windows
    event_windows = []
    for evt in events:
        event_windows.append((
            evt["switch_id"],
            evt["port"],
            evt["start_ts_us"] - window_us // 2,
            evt["end_ts_us"] + window_us // 2,
        ))

    event_samples = 0
    event_window_total_us = 0
    background_samples = 0
    min_ts = None
    max_ts = None

    for ts in telemetry:
        t = ts.get("hop_ts_us", 0)
        if min_ts is None or t < min_ts:
            min_ts = t
        if max_ts is None or t > max_ts:
            max_ts = t

        in_event_window = False
        for ew_sw, ew_port, ew_start, ew_end in event_windows:
            if (ts.get("switch_id", 0) == ew_sw and
                ts.get("egress_port", 0) == ew_port and
                ew_start <= t <= ew_end):
                in_event_window = True
                break

        if in_event_window:
            event_samples += 1
        else:
            background_samples += 1

    # Sum up event window durations
    for _, _, ew_start, ew_end in event_windows:
        event_window_total_us += (ew_end - ew_start)

    total_duration_us = (max_ts - min_ts) if (min_ts and max_ts) else 1
    background_duration_us = max(total_duration_us - event_window_total_us, 1)

    return {
        "event_window_samples": event_samples,
        "event_window_density_per_ms": event_samples / (event_window_total_us / 1000) if event_window_total_us > 0 else 0.0,
        "background_samples": background_samples,
        "background_density_per_ms": background_samples / (background_duration_us / 1000) if background_duration_us > 0 else 0.0,
    }


def compute_all_metrics(
    oracle_csv: str,
    telemetry_csv: str,
    events_csv: str,
    config: dict | None = None,
) -> dict:
    """Compute all required metrics from raw data files.

    Args:
        oracle_csv: Path to oracle.csv.
        telemetry_csv: Path to telemetry_samples.csv.
        events_csv: Path to events.csv.
        config: Configuration dict (uses defaults if None).

    Returns:
        Dict of all metric results.
    """
    if config is None:
        # Load defaults
        config = {
            "queue": {
                "capacity_packets": 128,
                "event_threshold_packets": 96,
                "release_threshold_packets": 64,
            },
            "predictor": {"epoch_us": 5000, "near_horizon": 2, "far_horizon": 8},
            "packet": {"original_packet_size": 1000, "shim_bytes": 8, "hop_record_bytes": 12},
        }

    oracle = read_oracle(oracle_csv)
    telemetry = read_telemetry(telemetry_csv)
    events = read_events(events_csv)

    q_cfg = config["queue"]
    p_cfg = config["predictor"]
    pkt_cfg = config["packet"]

    lead_times = compute_lead_times(oracle, telemetry, events)
    prf = compute_predictive_precision_recall(
        oracle, events,
        q_event=q_cfg["event_threshold_packets"],
        near_horizon=p_cfg["near_horizon"],
        epoch_us=p_cfg["epoch_us"],
    )
    overhead = compute_telemetry_overhead(
        telemetry,
        total_packets=overhead_total(oracle_csv, telemetry_csv),
        original_packet_size=pkt_cfg["original_packet_size"],
        shim_bytes=pkt_cfg.get("shim_bytes", 8),
        hop_record_bytes=pkt_cfg.get("hop_record_bytes", 12),
    )
    state_occ = compute_state_occupancy(oracle)
    nmae = compute_nmae(oracle, telemetry, q_cap=q_cfg["capacity_packets"])
    peak_err = compute_peak_error(oracle, telemetry)
    density = compute_event_window_density(telemetry, events)

    return {
        "lead_times": lead_times,
        "precision_recall_f1": prf,
        "telemetry_overhead": overhead,
        "state_occupancy": state_occ,
        "nmae": nmae,
        "peak_error": peak_err,
        "event_window_density": density,
    }


def overhead_total(oracle_csv: str, telemetry_csv: str) -> int:
    """Estimate total packets from oracle and telemetry data."""
    try:
        with open(telemetry_csv) as f:
            reader = csv.DictReader(f)
            pkts = set()
            for row in reader:
                pkts.add(row.get("packet_num", 0))
            return max(len(pkts), 1)
    except (FileNotFoundError, KeyError):
        return 1


def main():
    parser = argparse.ArgumentParser(description="Compute PTT-INT metrics")
    parser.add_argument("--oracle", required=True, help="oracle.csv path")
    parser.add_argument("--telemetry", required=True, help="telemetry_samples.csv path")
    parser.add_argument("--events", required=True, help="events.csv path")
    parser.add_argument("--output", default="metrics.json", help="Output JSON path")
    parser.add_argument("--config", default=None, help="Config YAML path")
    args = parser.parse_args()

    config = None
    if args.config:
        import yaml
        with open(args.config) as f:
            config = yaml.safe_load(f)

    metrics = compute_all_metrics(
        args.oracle, args.telemetry, args.events, config
    )

    with open(args.output, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics saved to {args.output}")


# Import at end to avoid issues
import argparse


if __name__ == "__main__":
    main()
