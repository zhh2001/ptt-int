#!/usr/bin/env python3
"""Run experiment matrix: repeated seeded experiments.

Executes multiple runs across schemes, workloads, and seeds.
Supports RQ-driven experiment matrices (E1-E4), microburst, and sensitivity.

Features:
- Randomized run order (shuffle, not sequential by scheme)
- Cooldown between runs
- Per-topology aggregate after topology completes
- Error markers for failed runs
"""

import sys
import os
import time
import json
import yaml
import random
import argparse
import itertools
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from experiments.run_one import run_experiment, SCHEME_MAP


def load_config(config_path: str = None) -> dict:
    if config_path is None:
        config_path = REPO_ROOT / "config" / "default.yaml"
    with open(config_path) as f:
        return yaml.safe_load(f)


def run_matrix(
    experiment_name: str,
    schemes: list[str],
    workloads: list[str],
    seeds: list[int],
    topology: str = "single_bottleneck",
    duration_s: float = 30.0,
    bottleneck_rate_pps: int = 100,
    config: dict = None,
    base_output: str = None,
    shuffle: bool = True,
    cooldown_s: float = 2.0,
) -> dict:
    """Execute a matrix of experiments.

    Args:
        experiment_name: Name for output grouping (e.g. "e1_single_bottleneck").
        schemes: List of scheme names.
        workloads: List of workload names.
        seeds: List of PRNG seeds.
        topology: Topology name.
        duration_s: Experiment duration in seconds.
        bottleneck_rate_pps: Bottleneck service rate in pps.
        config: Resolved config dict.
        base_output: Base output directory.
        shuffle: Randomize run order.
        cooldown_s: Cooldown between runs in seconds.

    Returns:
        Dict with results summary.
    """
    if config is None:
        config = load_config()

    if base_output is None:
        base_output = str(REPO_ROOT / "results" / "raw")

    # Build run list
    runs = []
    for scheme, workload, seed in itertools.product(schemes, workloads, seeds):
        runs.append({
            "scheme": scheme,
            "workload": workload,
            "seed": seed,
        })

    if shuffle:
        rng = random.Random(42)
        rng.shuffle(runs)

    total = len(runs)
    print(f"=== Experiment Matrix: {experiment_name} ===")
    print(f"    Total runs: {total}")
    print(f"    Schemes: {schemes}")
    print(f"    Workloads: {workloads}")
    print(f"    Seeds: {min(seeds)}-{max(seeds)} ({len(seeds)} values)")
    print(f"    Topology: {topology}")
    print(f"    Shuffle: {shuffle}")
    print()

    results_dirs = []
    failures = []
    start_time = time.time()

    for i, run in enumerate(runs):
        scheme = run["scheme"]
        workload = run["workload"]
        seed = run["seed"]

        output_dir = Path(base_output) / experiment_name / scheme / workload / str(seed)
        output_dir.mkdir(parents=True, exist_ok=True)

        elapsed = time.time() - start_time
        eta = (elapsed / max(i, 1)) * (total - i) if i > 0 else 0
        print(f"[{i+1}/{total}] {scheme:12s} {workload:16s} seed={seed:3d}  "
              f"(elapsed: {elapsed:.0f}s, ETA: {eta:.0f}s)")

        try:
            result_dir = run_experiment(
                scheme=scheme,
                seed=seed,
                workload=workload,
                topology_name=topology,
                duration_s=duration_s,
                output_dir=str(output_dir),
                config=config,
                bottleneck_rate_pps=bottleneck_rate_pps,
            )
            results_dirs.append(result_dir)
        except Exception as e:
            print(f"  FAILED: {e}", file=sys.stderr)
            # Write error marker
            with open(output_dir / "error.txt", "w") as f:
                f.write(f"Run failed: {e}\n")
            failures.append({**run, "error": str(e)})
            results_dirs.append(str(output_dir))

        # Cooldown to avoid resource exhaustion
        if cooldown_s > 0 and i < total - 1:
            time.sleep(cooldown_s)

    # Write matrix summary
    summary = {
        "experiment": experiment_name,
        "date": datetime.now().isoformat(),
        "total_runs": total,
        "completed": len(results_dirs) - len(failures),
        "failed": len(failures),
        "schemes": schemes,
        "workloads": workloads,
        "seeds": list(seeds),
        "topology": topology,
        "duration_s": duration_s,
        "bottleneck_rate_pps": bottleneck_rate_pps,
        "elapsed_s": round(time.time() - start_time, 1),
        "results": results_dirs,
        "failures": failures,
    }

    summary_path = Path(base_output) / experiment_name / "matrix_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nMatrix complete: {summary['completed']}/{total} runs succeeded "
          f"({summary['elapsed_s']:.0f}s)")
    if failures:
        print(f"Failures: {len(failures)}")
        for f in failures:
            print(f"  - {f['scheme']} {f['workload']} seed={f['seed']}: {f['error'][:100]}")
    print(f"Summary: {summary_path}")

    return summary


def main():
    parser = argparse.ArgumentParser(description="PTT-INT experiment matrix runner")
    parser.add_argument("--experiment", default="main",
                        help="Experiment name for output grouping")
    parser.add_argument("--schemes", nargs="+",
                        default=["PTT", "REACTIVE", "FULL"],
                        help="Schemes to run")
    parser.add_argument("--workloads", nargs="+",
                        default=["ramp_medium"],
                        help="Workloads to run")
    parser.add_argument("--seeds", type=str, default="1..5",
                        help="Seed range: '1..5' or space-separated list")
    parser.add_argument("--topology", default="single_bottleneck",
                        choices=["single_bottleneck", "incast", "leaf_spine"])
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--bottleneck-rate-pps", type=int, default=100)
    parser.add_argument("--output", default=None)
    parser.add_argument("--no-shuffle", action="store_true",
                        help="Disable random run order")
    parser.add_argument("--cooldown", type=float, default=2.0)
    parser.add_argument("--microburst", action="store_true",
                        help="Use microburst workloads (for E2)")
    parser.add_argument("--sensitivity", action="store_true",
                        help="Run sensitivity/ablation matrix (for E3)")
    args = parser.parse_args()

    config = load_config()

    # Parse seeds
    if ".." in args.seeds:
        parts = args.seeds.split("..")
        seeds = list(range(int(parts[0]), int(parts[1]) + 1))
    else:
        seeds = [int(s) for s in args.seeds.replace(",", " ").split()]

    # Determine workloads
    if args.microburst:
        workloads = [
            "microburst_2C_5ms", "microburst_2C_10ms", "microburst_2C_20ms", "microburst_2C_50ms",
            "microburst_3C_5ms", "microburst_3C_10ms", "microburst_3C_20ms", "microburst_3C_50ms",
            "microburst_4C_5ms", "microburst_4C_10ms", "microburst_4C_20ms", "microburst_4C_50ms",
        ]
    elif args.sensitivity:
        workloads = ["ramp_medium"]  # fixed workload for sensitivity
    else:
        workloads = args.workloads

    topology = args.topology
    if args.microburst:
        topology = "incast"

    summary = run_matrix(
        experiment_name=args.experiment,
        schemes=args.schemes,
        workloads=workloads,
        seeds=seeds,
        topology=topology,
        duration_s=args.duration,
        bottleneck_rate_pps=args.bottleneck_rate_pps,
        config=config,
        base_output=args.output,
        shuffle=not args.no_shuffle,
        cooldown_s=args.cooldown,
    )

    if summary["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
