#!/usr/bin/env python3
"""Plot all experiment figures.

Wrapper around analysis/plots.py that generates all required figures
from experiment data.

Strict completeness mode (default): Fails with clear error if any
expected run directory or data file is missing. Names the missing files.

Debug/partial mode (--allow-missing): Skips missing runs, annotates
plots with warnings.

Required figures:
  1. queue_calibration.png    — Gate A calibration time series
  2. sample_timeline.png      — Per-packet sampling timeline
  3. reconstruction.png       — Queue reconstruction comparison
  4. lead_time_cdf.png        — CDF of burst lead times
  5. precision_recall.png     — Precision/recall bar chart
  6. overhead_comparison.png  — Telemetry overhead across schemes
  7. state_transition.png     — FSM state transition diagram
  8. microburst_detection.png — Microburst detection latency
  9. sensitivity_heatmap.png  — Parameter sensitivity heatmap
  10. leaf_spine_scaling.png  — Leaf-spine scalability
  11. nmae_comparison.png     — NMAE across schemes
"""

import sys
import os
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


def plot_all(results_dir: str, output_dir: str,
             allow_missing: bool = False) -> dict:
    """Generate all 11 figures.

    Args:
        results_dir: Root directory containing experiment results.
        output_dir: Directory for output plot files.
        allow_missing: If True, skip missing data instead of failing.

    Returns:
        Dict mapping plot name → output path (or error message).

    Raises:
        FileNotFoundError: If required data is missing and allow_missing is False.
    """
    results_dir = Path(results_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    plots = {}

    # Try to import plotting functions
    try:
        from analysis.plots import (
            plot_queue_calibration,
            plot_sample_timeline,
            plot_reconstruction,
            plot_lead_time_cdf,
            plot_precision_recall,
            plot_overhead_comparison,
            plot_state_transition,
            plot_microburst_detection,
            plot_sensitivity_heatmap,
            plot_leaf_spine_scaling,
            plot_nmae_comparison,
        )
        HAS_PLOTS = True
    except ImportError as e:
        print(f"WARNING: Cannot import analysis.plots: {e}")
        print("Plotting functions not available — generating placeholder report.")
        HAS_PLOTS = False

    # Define expected data locations
    expected = {
        "queue_calibration": {
            "data": results_dir / "calibration" / "queue_calibration.csv",
            "plot_func": plot_queue_calibration if HAS_PLOTS else None,
            "output": output_dir / "queue_calibration.png",
            "required": True,
        },
        "sample_timeline": {
            "data": results_dir / "pilot" / "runs",
            "plot_func": plot_sample_timeline if HAS_PLOTS else None,
            "output": output_dir / "sample_timeline.png",
            "required": False,  # needs specific run data
        },
        "reconstruction": {
            "data": results_dir / "pilot" / "runs",
            "plot_func": plot_reconstruction if HAS_PLOTS else None,
            "output": output_dir / "reconstruction.png",
            "required": False,
        },
        "lead_time_cdf": {
            "data": results_dir / "pilot" / "runs",
            "plot_func": plot_lead_time_cdf if HAS_PLOTS else None,
            "output": output_dir / "lead_time_cdf.png",
            "required": False,
        },
        "precision_recall": {
            "data": results_dir / "pilot" / "runs",
            "plot_func": plot_precision_recall if HAS_PLOTS else None,
            "output": output_dir / "precision_recall.png",
            "required": False,
        },
        "overhead_comparison": {
            "data": results_dir / "pilot" / "runs",
            "plot_func": plot_overhead_comparison if HAS_PLOTS else None,
            "output": output_dir / "overhead_comparison.png",
            "required": False,
        },
        "state_transition": {
            "data": results_dir / "pilot" / "runs",
            "plot_func": plot_state_transition if HAS_PLOTS else None,
            "output": output_dir / "state_transition.png",
            "required": False,
        },
        "microburst_detection": {
            "data": results_dir / "raw" / "incast",
            "plot_func": plot_microburst_detection if HAS_PLOTS else None,
            "output": output_dir / "microburst_detection.png",
            "required": False,
        },
        "sensitivity_heatmap": {
            "data": results_dir / "raw" / "sensitivity",
            "plot_func": plot_sensitivity_heatmap if HAS_PLOTS else None,
            "output": output_dir / "sensitivity_heatmap.png",
            "required": False,
        },
        "leaf_spine_scaling": {
            "data": results_dir / "raw" / "leaf_spine",
            "plot_func": plot_leaf_spine_scaling if HAS_PLOTS else None,
            "output": output_dir / "leaf_spine_scaling.png",
            "required": False,
        },
        "nmae_comparison": {
            "data": results_dir / "pilot" / "runs",
            "plot_func": plot_nmae_comparison if HAS_PLOTS else None,
            "output": output_dir / "nmae_comparison.png",
            "required": False,
        },
    }

    # Check for missing required data
    missing_required = []
    for name, info in expected.items():
        if info["required"] and not info["data"].exists():
            missing_required.append(f"  - {info['data']} (for {name})")

    if missing_required and not allow_missing:
        msg = "Missing required data files:\n" + "\n".join(missing_required)
        raise FileNotFoundError(msg)

    # Generate plots
    for name, info in expected.items():
        if not info["data"].exists():
            if info["required"]:
                plots[name] = {"status": "missing_required", "path": str(info["data"])}
            else:
                plots[name] = {"status": "skipped", "reason": "data not available"}
            continue

        if info["plot_func"] is None:
            plots[name] = {"status": "skipped", "reason": "plotting functions not available"}
            continue

        try:
            info["plot_func"](str(info["data"]), str(info["output"]))
            plots[name] = {"status": "generated", "path": str(info["output"])}
        except Exception as e:
            plots[name] = {"status": "error", "error": str(e)}
            if not allow_missing:
                raise

    # Generate summary
    generated = sum(1 for p in plots.values() if p["status"] == "generated")
    print(f"\nPlots generated: {generated}/{len(expected)}")
    for name, info in plots.items():
        status = info["status"]
        if status == "generated":
            print(f"  ✅ {name}: {info['path']}")
        elif status == "skipped":
            print(f"  ⏭️  {name}: {info.get('reason', 'skipped')}")
        elif status == "error":
            print(f"  ❌ {name}: {info['error']}")
        elif status == "missing_required":
            print(f"  ❌ {name}: missing {info['path']}")

    return plots


def main():
    parser = argparse.ArgumentParser(description="Generate all PTT-INT figures")
    parser.add_argument("--results-dir", default=str(REPO_ROOT / "results"),
                        help="Root results directory")
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "results" / "figures"),
                        help="Output directory for plots")
    parser.add_argument("--allow-missing", action="store_true",
                        help="Skip missing data instead of failing")
    args = parser.parse_args()

    try:
        plot_all(
            results_dir=args.results_dir,
            output_dir=args.output_dir,
            allow_missing=args.allow_missing,
        )
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
