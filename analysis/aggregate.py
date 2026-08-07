#!/usr/bin/env python3
"""Aggregate metrics across multiple experiment runs.

Reads metrics.json from multiple run directories and computes
summary statistics (median, IQR, 95% CI via bootstrap).
"""

import json
import sys
import argparse
import numpy as np
from pathlib import Path


def bootstrap_ci(values: list[float], n_bootstrap: int = 2000,
                 ci: float = 95.0) -> tuple[float, float]:
    """Compute bootstrap confidence interval for the median."""
    if len(values) < 3:
        return (np.median(values), np.median(values))
    rng = np.random.RandomState(42)
    medians = []
    for _ in range(n_bootstrap):
        sample = rng.choice(values, size=len(values), replace=True)
        medians.append(np.median(sample))
    lower = (100 - ci) / 2
    upper = 100 - lower
    return (np.percentile(medians, lower), np.percentile(medians, upper))


def aggregate_metrics(run_dirs: list[str], metric_keys: list[str] | None = None):
    """Aggregate metrics from multiple run directories."""
    all_metrics = []
    for run_dir in run_dirs:
        metrics_path = Path(run_dir) / "metrics.json"
        manifest_path = Path(run_dir) / "manifest.json"
        if not metrics_path.exists():
            print(f"WARNING: No metrics.json in {run_dir}, skipping")
            continue
        with open(metrics_path) as f:
            data = json.load(f)
        meta = {}
        if manifest_path.exists():
            with open(manifest_path) as f:
                meta = json.load(f)
        data["_run_dir"] = str(run_dir)
        data["_scheme"] = meta.get("scheme", "unknown")
        data["_seed"] = meta.get("seed", 0)
        all_metrics.append(data)

    if not all_metrics:
        print("ERROR: No metrics found", file=sys.stderr)
        sys.exit(1)

    # Extract key metrics across runs
    summary = {}
    for key_path in [
        ("lead_times", "median_burst_lead_us"),
        ("lead_times", "positive_burst_ratio"),
        ("precision_recall_f1", "precision"),
        ("precision_recall_f1", "recall"),
        ("precision_recall_f1", "f1"),
        ("telemetry_overhead", "byte_overhead_ratio"),
        ("telemetry_overhead", "instrumented_ratio"),
        ("nmae", "NMAE"),
        ("peak_error", "peak_error"),
        ("state_occupancy", "P_BURST"),
        ("state_occupancy", "P_WATCH"),
    ]:
        values = []
        for m in all_metrics:
            v = m
            for k in key_path:
                v = v.get(k, {}) if isinstance(v, dict) else None
            if isinstance(v, (int, float)) and v is not None:
                values.append(v)

        if values:
            med = np.median(values)
            ci_lo, ci_hi = bootstrap_ci(values)
            name = ".".join(key_path)
            summary[name] = {
                "n": len(values),
                "median": float(med),
                "ci_95_lower": float(ci_lo),
                "ci_95_upper": float(ci_hi),
                "iqr": [float(np.percentile(values, 25)), float(np.percentile(values, 75))],
                "values": [float(v) for v in values],
            }

    return summary


def main():
    parser = argparse.ArgumentParser(description="Aggregate experiment metrics")
    parser.add_argument("run_dirs", nargs="+", help="Run directories")
    parser.add_argument("--output", default="aggregated_metrics.json",
                        help="Output JSON path")
    args = parser.parse_args()

    summary = aggregate_metrics(args.run_dirs)
    with open(args.output, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Aggregated {len(summary)} metrics from {len(args.run_dirs)} runs")


if __name__ == "__main__":
    main()
