#!/usr/bin/env python3
"""Queue reconstruction from telemetry samples using last-sample-hold.

Given oracle.csv and telemetry_samples.csv, reconstructs q_hat(t) and
computes per-timestep errors for monitoring accuracy analysis.
"""

import csv
import sys
import argparse
from pathlib import Path
from collections import defaultdict


def reconstruct_last_sample_hold(
    oracle_csv: str,
    telemetry_csv: str,
) -> list[dict]:
    """Reconstruct queue depth using last-sample-hold.

    For each oracle sample at time t, q_hat(t) = q(last_report <= t).

    Returns list of {ts_us, q_true, q_hat, abs_error, switch_id, port}.
    """
    # Read oracle
    oracle_rows = []
    with open(oracle_csv) as f:
        for row in csv.DictReader(f):
            oracle_rows.append({
                "switch_id": int(row["switch_id"]),
                "port": int(row["port"]),
                "ts_us": int(row["ts_us"]),
                "q_true": int(row["q"]),
            })

    # Read telemetry and build report timelines per (switch, port)
    reports = defaultdict(list)
    with open(telemetry_csv) as f:
        for row in csv.DictReader(f):
            key = (int(row.get("switch_id", 0)), int(row.get("egress_port", 0)))
            reports[key].append({
                "ts_us": int(row.get("hop_ts_us", 0)),
                "q": int(row.get("qdepth", 0)),
            })

    # Sort reports by timestamp
    for key in reports:
        reports[key].sort(key=lambda r: r["ts_us"])

    # Reconstruct
    result = []
    for o in oracle_rows:
        key = (o["switch_id"], o["port"])
        rep_list = reports.get(key, [])

        q_hat = None
        for r in rep_list:
            if r["ts_us"] <= o["ts_us"]:
                q_hat = r["q"]
            else:
                break

        if q_hat is not None:
            result.append({
                "switch_id": o["switch_id"],
                "port": o["port"],
                "ts_us": o["ts_us"],
                "q_true": o["q_true"],
                "q_hat": q_hat,
                "abs_error": abs(o["q_true"] - q_hat),
            })

    return result


def main():
    parser = argparse.ArgumentParser(description="Reconstruct queue from telemetry")
    parser.add_argument("--oracle", required=True, help="oracle.csv path")
    parser.add_argument("--telemetry", required=True, help="telemetry_samples.csv path")
    parser.add_argument("--output", default="reconstruction.csv", help="Output CSV")
    args = parser.parse_args()

    results = reconstruct_last_sample_hold(args.oracle, args.telemetry)

    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "switch_id", "port", "ts_us", "q_true", "q_hat", "abs_error"
        ])
        writer.writeheader()
        writer.writerows(results)

    if results:
        mae = sum(r["abs_error"] for r in results) / len(results)
        print(f"Reconstructed {len(results)} points, MAE={mae:.2f} pkts")
    else:
        print("No overlapping oracle-telemetry points found")


if __name__ == "__main__":
    main()
