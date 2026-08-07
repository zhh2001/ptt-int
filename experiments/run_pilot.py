#!/usr/bin/env python3
"""Pilot experiment orchestrator.

Runs a small feasibility experiment:
- Single bottleneck topology
- 3 ramp workloads (slow/medium/fast)
- 2 schemes (REACTIVE, PTT)
- 5 seeds each
Total: 2 × 3 × 5 = 30 runs

Go/no-go check (feasibility/tuning gate, NOT hard pass/fail):
  REQUIRED (blocking):
  1. PTT shows positive burst lead time on predictable ramp events
  2. REACTIVE shows approximately zero lead time
  3. No state oscillation under stable traffic
  4. No pathological false BURST activation under stable_80

  REPORTED (not blocking):
  - Precision, recall, F1 at default horizon
  - State occupancy distribution
  - Telemetry overhead ratios
  - NMAE and peak reconstruction error

Output: pilot_results.json + pilot_go_nogo.md
"""

import sys
import os
import time
import json
import csv
import argparse
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from experiments.run_one import run_experiment


# ── pilot configuration ───────────────────────────────────────────────────

PILOT_SCHEMES = ["REACTIVE", "PTT"]
PILOT_WORKLOADS = ["ramp_slow", "ramp_medium", "ramp_fast"]
PILOT_SEEDS = [1, 2, 3, 4, 5]
STABLE_WORKLOAD = "stable_80"
BOTTLENECK_RATE_PPS = 100
DURATION_S = 30


def run_pilot(output_dir: str, config: dict = None) -> dict:
    """Run the full pilot experiment matrix.

    Returns dict with all results and go/no-go verdict.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_runs = []
    run_dirs = []

    total = len(PILOT_SCHEMES) * len(PILOT_WORKLOADS) * len(PILOT_SEEDS)
    n = 0

    print(f"=== Pilot Experiment: {total} runs ===")

    for scheme in PILOT_SCHEMES:
        for workload in PILOT_WORKLOADS:
            for seed in PILOT_SEEDS:
                n += 1
                print(f"\n[{n}/{total}] {scheme} {workload} seed={seed}")

                run_output = output_dir / "runs" / scheme / workload / str(seed)
                try:
                    result_path = run_experiment(
                        scheme=scheme,
                        seed=seed,
                        workload=workload,
                        topology_name="single_bottleneck",
                        duration_s=DURATION_S,
                        output_dir=str(run_output),
                        config=config,
                        bottleneck_rate_pps=BOTTLENECK_RATE_PPS,
                    )
                    run_dirs.append(result_path)
                    all_runs.append({
                        "scheme": scheme,
                        "workload": workload,
                        "seed": seed,
                        "output_dir": result_path,
                        "status": "completed",
                    })
                except Exception as e:
                    print(f"  FAILED: {e}")
                    all_runs.append({
                        "scheme": scheme,
                        "workload": workload,
                        "seed": seed,
                        "error": str(e),
                        "status": "failed",
                    })

    # Also run stable_80 check for pathological behavior detection
    print(f"\n--- Stability check: stable_80 ---")
    for scheme in PILOT_SCHEMES:
        for seed in [1, 2, 3]:
            print(f"  {scheme} stable_80 seed={seed}")
            run_output = output_dir / "runs" / scheme / "stable_80" / str(seed)
            try:
                result_path = run_experiment(
                    scheme=scheme,
                    seed=seed,
                    workload="stable_80",
                    topology_name="single_bottleneck",
                    duration_s=DURATION_S,
                    output_dir=str(run_output),
                    config=config,
                    bottleneck_rate_pps=BOTTLENECK_RATE_PPS,
                )
                all_runs.append({
                    "scheme": scheme,
                    "workload": "stable_80",
                    "seed": seed,
                    "output_dir": result_path,
                    "status": "completed",
                })
            except Exception as e:
                print(f"    FAILED: {e}")
                all_runs.append({
                    "scheme": scheme,
                    "workload": "stable_80",
                    "seed": seed,
                    "error": str(e),
                    "status": "failed",
                })

    # ── Aggregate results ────────────────────────────────────────────
    go_nogo = _evaluate_pilot(all_runs, output_dir)

    # Save results
    pilot_results = {
        "timestamp": datetime.now().isoformat(),
        "total_runs": len(all_runs),
        "completed": sum(1 for r in all_runs if r["status"] == "completed"),
        "failed": sum(1 for r in all_runs if r["status"] == "failed"),
        "runs": all_runs,
        "go_nogo": go_nogo,
    }

    with open(output_dir / "pilot_results.json", "w") as f:
        json.dump(pilot_results, f, indent=2, default=str)

    # Generate go/no-go report
    md = _generate_go_nogo_md(pilot_results)
    with open(output_dir / "pilot_go_nogo.md", "w") as f:
        f.write(md)

    print(f"\n=== Pilot complete: {pilot_results['completed']}/{pilot_results['total_runs']} completed ===")
    print(f"Go decision: {'GO' if go_nogo['go'] else 'NO-GO'}")
    print(f"Report: {output_dir / 'pilot_go_nogo.md'}")

    return pilot_results


def _evaluate_pilot(runs: list, output_dir: Path) -> dict:
    """Evaluate pilot results for go/no-go decision.

    This is a FEASIBILITY/TUNING gate, not a hard pass/fail.
    """
    completed = [r for r in runs if r["status"] == "completed"]

    if len(completed) < 10:
        return {
            "go": False,
            "verdict": "NO-GO: Insufficient completed runs",
            "reason": f"Only {len(completed)} runs completed successfully. Need at least 10.",
            "checks": {},
        }

    checks = {}

    # Check 1: PTT burst lead time on ramp workloads
    ptt_ramp_runs = [r for r in completed
                     if r["scheme"] == "PTT" and "ramp" in r["workload"]]
    reactive_ramp_runs = [r for r in completed
                          if r["scheme"] == "REACTIVE" and "ramp" in r["workload"]]

    # Try to load metrics from each run
    ptt_lead_times = []
    reactive_lead_times = []

    for run in ptt_ramp_runs + reactive_ramp_runs:
        metrics_path = Path(run["output_dir"]) / "metrics.json"
        events_path = Path(run["output_dir"]) / "events.csv"
        if metrics_path.exists():
            try:
                with open(metrics_path) as f:
                    metrics = json.load(f)
                # Try to extract lead time from metrics
                lt = metrics.get("burst_lead_time_ms") or metrics.get("mean_lead_time_ms")
                if lt is not None:
                    if run["scheme"] == "PTT":
                        ptt_lead_times.append(lt)
                    else:
                        reactive_lead_times.append(lt)
            except Exception:
                pass

    # Check 1: PTT shows positive lead time
    if ptt_lead_times:
        mean_ptt_lead = sum(ptt_lead_times) / len(ptt_lead_times)
        checks["ptt_positive_lead"] = {
            "passed": mean_ptt_lead > 0,
            "detail": f"Mean PTT lead time: {mean_ptt_lead:.1f}ms ({len(ptt_lead_times)} runs)",
            "blocking": True,
        }
    else:
        checks["ptt_positive_lead"] = {
            "passed": False,
            "detail": "No lead time data available — metrics may not have been computed",
            "blocking": True,
        }

    # Check 2: REACTIVE shows approximately zero lead
    if reactive_lead_times:
        mean_reactive_lead = sum(reactive_lead_times) / len(reactive_lead_times)
        checks["reactive_zero_lead"] = {
            "passed": abs(mean_reactive_lead) < 100,  # within 100ms
            "detail": f"Mean REACTIVE lead time: {mean_reactive_lead:.1f}ms ({len(reactive_lead_times)} runs)",
            "blocking": True,
        }
    else:
        checks["reactive_zero_lead"] = {
            "passed": False,
            "detail": "No REACTIVE lead time data",
            "blocking": True,
        }

    # Check 3: No state oscillation under stable traffic
    # We check the state distribution in telemetry samples for stable_80 runs
    stable_runs = [r for r in completed if r["workload"] == "stable_80"]
    oscillation_warnings = 0
    for run in stable_runs:
        telemetry_path = Path(run["output_dir"]) / "telemetry_samples.csv"
        if telemetry_path.exists():
            try:
                with open(telemetry_path) as f:
                    reader = csv.DictReader(f)
                    states = defaultdict(int)
                    for row in reader:
                        state = row.get("state", "")
                        states[state] += 1
                # Check for rapid state transitions
                total = sum(states.values())
                if total > 0:
                    quiet_pct = states.get("0", 0) / total
                    burst_pct = states.get("2", 0) / total
                    # If BURST > 10% under stable_80, that's a warning
                    if burst_pct > 0.10:
                        oscillation_warnings += 1
            except Exception:
                pass

    checks["no_stable_oscillation"] = {
        "passed": oscillation_warnings == 0,
        "detail": f"{oscillation_warnings} runs with BURST > 10% under stable_80",
        "blocking": True,
    }

    # Check 4: No pathological false BURST
    checks["no_pathological_burst"] = {
        "passed": oscillation_warnings <= 1,
        "detail": f"{oscillation_warnings} potential false burst detections",
        "blocking": True,
    }

    # Determine go/no-go
    blocking_checks = {k: v for k, v in checks.items() if v.get("blocking")}
    all_blocking_pass = all(c["passed"] for c in blocking_checks.values())

    return {
        "go": all_blocking_pass,
        "verdict": "GO" if all_blocking_pass else "NO-GO — review required",
        "reason": "All blocking checks passed" if all_blocking_pass
                  else f"Failed checks: {[k for k, v in blocking_checks.items() if not v['passed']]}",
        "checks": checks,
    }


def _generate_go_nogo_md(results: dict) -> str:
    """Generate Markdown go/no-go report."""
    gn = results["go_nogo"]
    checks_md = ""
    for name, check in gn.get("checks", {}).items():
        icon = "✅" if check["passed"] else "❌"
        blocking = " (BLOCKING)" if check.get("blocking") else ""
        checks_md += f"| {name}{blocking} | {icon} | {check['detail']} |\n"

    return f"""# Pilot Experiment Go/No-Go Report

**Date:** {results['timestamp']}
**Verdict:** **{gn['verdict']}**
**Reason:** {gn['reason']}

## Summary

| Metric | Value |
|--------|-------|
| Total runs | {results['total_runs']} |
| Completed | {results['completed']} |
| Failed | {results['failed']} |

## Feasibility Checks

| Check | Status | Detail |
|-------|--------|--------|
{checks_md}

## Run Details

| Scheme | Workload | Seed | Status |
|--------|----------|------|--------|
"""
    for run in results["runs"]:
        md += f"| {run['scheme']} | {run['workload']} | {run['seed']} | {run['status']} |\n"

    md += """
## Decision

"""
    if gn["go"]:
        md += "**GO** — Proceed to main experiment matrix (E1-E4). All blocking checks passed.\n"
    else:
        md += "**NO-GO** — Review the failed checks above before proceeding. This is a feasibility/tuning gate, not a hard failure. Adjust PTT parameters and re-run the pilot.\n"

    md += """
## Notes

- This is a FEASIBILITY/TUNING gate, not a hard pass/fail criterion.
- If precision < 0.8, that's a tuning input, not a failure.
- Raw data is available in the `runs/` directory for manual review.
- Do NOT proceed to E1-E4 main experiments until this report has been reviewed.
"""
    return md


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PTT-INT Pilot Experiment")
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "results" / "pilot"),
                        help="Output directory for pilot results")
    parser.add_argument("--config", default=None,
                        help="Config file path (default: config/default.yaml)")
    args = parser.parse_args()

    import yaml
    config = None
    if args.config:
        with open(args.config) as f:
            config = yaml.safe_load(f)

    results = run_pilot(output_dir=args.output_dir, config=config)
    gn = results["go_nogo"]
    if not gn["go"]:
        print(f"\nNO-GO: {gn['reason']}")
        sys.exit(1)


if __name__ == "__main__":
    main()
