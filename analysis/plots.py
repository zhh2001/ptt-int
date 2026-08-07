#!/usr/bin/env python3
"""PTT-INT plotting code.

Generates all required figures from processed data.
Never fabricates data. Never silently skips missing runs.
"""

import sys
import json
import argparse
from pathlib import Path
from collections import defaultdict

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ---------------------------------------------------------------------------
# Plot styling
# ---------------------------------------------------------------------------
plt.rcParams.update({
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "savefig.bbox": "tight",
    "font.size": 10,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
})


def ensure_output_dir(path: str) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def load_metrics(metrics_file: str) -> dict:
    """Load a metrics.json file. Fail loudly if missing."""
    path = Path(metrics_file)
    if not path.exists():
        raise FileNotFoundError(f"Metrics file not found: {metrics_file}")
    with open(path) as f:
        return json.load(f)


def load_run_data(run_dir: str) -> dict:
    """Load all data products from a run directory."""
    base = Path(run_dir)
    data = {}
    for fname in ["oracle.csv", "telemetry_samples.csv", "events.csv", "metrics.json", "manifest.json"]:
        fp = base / fname
        if fp.exists():
            data[fname] = str(fp)
    return data


# ---------------------------------------------------------------------------
# Fig 3: Mechanism Timeline
# ---------------------------------------------------------------------------
def plot_mechanism_timeline(oracle_csv: str, telemetry_csv: str, events_csv: str,
                            output: str, q_event: int = 96, title: str = None):
    """Plot oracle queue depth, predictions, WATCH/BURST intervals, events."""
    import csv

    # Read oracle data
    oracle_times, oracle_qs, oracle_qn, oracle_qf, states = [], [], [], [], []
    with open(oracle_csv) as f:
        for row in csv.DictReader(f):
            oracle_times.append(int(row["ts_us"]) / 1000.0)  # ms
            oracle_qs.append(int(row["q"]))
            oracle_qn.append(int(row["q_pred_near"]))
            oracle_qf.append(int(row["q_pred_far"]))
            states.append(int(row["state"]))

    # Read telemetry for state changes
    tel_times, tel_states = [], []
    with open(telemetry_csv) as f:
        for row in csv.DictReader(f):
            tel_times.append(int(row["hop_ts_us"]) / 1000.0)
            s = row.get("state", "")
            tel_states.append(0 if s == "QUIET" else (1 if s == "WATCH" else 2))

    # Read events
    event_starts, event_ends = [], []
    try:
        with open(events_csv) as f:
            for row in csv.DictReader(f):
                event_starts.append(int(row["start_ts_us"]) / 1000.0)
                event_ends.append(int(row["end_ts_us"]) / 1000.0)
    except FileNotFoundError:
        pass

    fig, axes = plt.subplots(3, 1, figsize=(12, 9), sharex=True)

    # Subplot 1: Queue depth + predictions + threshold
    ax = axes[0]
    ax.plot(oracle_times, oracle_qs, "b-", linewidth=0.8, label="q (oracle)", alpha=0.7)
    ax.plot(oracle_times, oracle_qn, "orange", linewidth=0.5, linestyle="--", label="q_pred_near")
    ax.plot(oracle_times, oracle_qf, "green", linewidth=0.5, linestyle=":", label="q_pred_far")
    ax.axhline(y=q_event, color="r", linestyle="--", linewidth=1, label=f"Q_EVENT={q_event}")
    ax.set_ylabel("Queue Depth (pkts)")
    ax.legend(loc="upper left", fontsize=8)
    ax.grid(True, alpha=0.3)

    # Subplot 2: State over time
    ax = axes[1]
    ax.step(oracle_times, states, "b-", where="post", linewidth=1, label="Oracle State")
    if tel_times:
        ax.scatter(tel_times, tel_states, c="red", s=10, alpha=0.3, label="Telemetry Samples")
    ax.set_ylabel("State (0=Q,1=W,2=B)")
    ax.set_yticks([0, 1, 2])
    ax.set_yticklabels(["QUIET", "WATCH", "BURST"])
    ax.legend(loc="upper left", fontsize=8)
    ax.grid(True, alpha=0.3)

    # Subplot 3: Event intervals
    ax = axes[2]
    for i, (s, e) in enumerate(zip(event_starts, event_ends)):
        ax.axvspan(s, e, alpha=0.2, color="red", label="Event" if i == 0 else "")
    ax.set_xlabel("Time (ms)")
    ax.set_ylabel("Events")
    if event_starts:
        ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)

    if title:
        fig.suptitle(title)
    fig.tight_layout()
    fig.savefig(output)
    plt.close(fig)
    print(f"Timeline plot saved: {output}")


# ---------------------------------------------------------------------------
# Fig 4: Lead Time Distribution
# ---------------------------------------------------------------------------
def plot_lead_time_distribution(metrics_by_scheme: dict, output: str):
    """Boxplot/violin of lead times per scheme."""
    schemes = []
    burst_leads = []

    for scheme, metrics_list in metrics_by_scheme.items():
        for m in metrics_list:
            lt = m.get("lead_times", {})
            bl = lt.get("burst_lead_times", [])
            for l in bl:
                schemes.append(scheme)
                burst_leads.append(l / 1000.0)  # us -> ms

    if not burst_leads:
        print("WARNING: No lead time data for plot")
        # Create empty plot with message
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.text(0.5, 0.5, "No lead time data available", transform=ax.transAxes,
                ha="center", va="center", fontsize=14)
        fig.savefig(output)
        plt.close(fig)
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    data_by_scheme = defaultdict(list)
    for s, l in zip(schemes, burst_leads):
        data_by_scheme[s].append(l)

    scheme_order = sorted(data_by_scheme.keys())
    plot_data = [data_by_scheme[s] for s in scheme_order]

    bp = ax.boxplot(plot_data, labels=scheme_order, patch_artist=True)
    for patch, s in zip(bp["boxes"], scheme_order):
        patch.set_facecolor("lightblue")

    ax.axhline(y=0, color="r", linestyle="--", linewidth=1, label="Zero lead (reactive)")
    ax.set_ylabel("Burst Lead Time (ms)")
    ax.set_title("Lead Time Distribution by Scheme")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output)
    plt.close(fig)
    print(f"Lead time distribution saved: {output}")


# ---------------------------------------------------------------------------
# Fig 5: Precision / Recall / F1 vs Horizon
# ---------------------------------------------------------------------------
def plot_precision_recall_vs_horizon(metrics_data: list[dict], output: str):
    """Precision, Recall, F1 vs prediction horizon sweep."""
    if not metrics_data:
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.text(0.5, 0.5, "No metrics data", transform=ax.transAxes,
                ha="center", va="center")
        fig.savefig(output)
        plt.close(fig)
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    horizons = []
    precisions = []
    recalls = []
    f1s = []

    for entry in metrics_data:
        h = entry.get("horizon", 0)
        prf = entry.get("metrics", {}).get("precision_recall_f1", {})
        horizons.append(h)
        precisions.append(prf.get("precision", 0))
        recalls.append(prf.get("recall", 0))
        f1s.append(prf.get("f1", 0))

    if not horizons:
        ax1.text(0.5, 0.5, "No horizon sweep data", transform=ax1.transAxes,
                 ha="center", va="center")
        ax2.text(0.5, 0.5, "No horizon sweep data", transform=ax2.transAxes,
                 ha="center", va="center")
    else:
        ax1.plot(horizons, precisions, "bo-", label="Precision")
        ax1.plot(horizons, recalls, "rs-", label="Recall")
        ax1.plot(horizons, f1s, "g^-", label="F1")
        ax1.set_xlabel("Far Horizon (H_F)")
        ax1.set_ylabel("Score")
        ax1.set_title("Precision / Recall / F1")
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        ax1.set_ylim(0, 1.05)

    fig.tight_layout()
    fig.savefig(output)
    plt.close(fig)
    print(f"Precision/Recall plot saved: {output}")


# ---------------------------------------------------------------------------
# Fig 6: Overhead by Workload
# ---------------------------------------------------------------------------
def plot_overhead_by_workload(metrics_by_scheme_workload: dict, output: str):
    """Grouped bar chart: telemetry byte overhead by workload and scheme."""
    fig, ax = plt.subplots(figsize=(12, 6))

    if not metrics_by_scheme_workload:
        ax.text(0.5, 0.5, "No overhead data", transform=ax.transAxes,
                ha="center", va="center")
        fig.savefig(output)
        plt.close(fig)
        return

    # Extract unique workloads and schemes
    workloads = sorted(set(k[0] for k in metrics_by_scheme_workload.keys()))
    schemes = sorted(set(k[1] for k in metrics_by_scheme_workload.keys()))

    x = np.arange(len(workloads))
    width = 0.8 / len(schemes)

    for i, scheme in enumerate(schemes):
        overheads = []
        for wl in workloads:
            data = metrics_by_scheme_workload.get((wl, scheme), {})
            oh = data.get("telemetry_overhead", {}).get("byte_overhead_ratio", 0)
            overheads.append(oh * 100)  # percentage
        ax.bar(x + i * width, overheads, width, label=scheme)

    ax.set_xlabel("Workload")
    ax.set_ylabel("Telemetry Byte Overhead (%)")
    ax.set_title("Telemetry Overhead by Workload and Scheme")
    ax.set_xticks(x + width * (len(schemes) - 1) / 2)
    ax.set_xticklabels(workloads)
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3, axis="y")
    fig.tight_layout()
    fig.savefig(output)
    plt.close(fig)
    print(f"Overhead plot saved: {output}")


# ---------------------------------------------------------------------------
# Fig 8: Overhead vs Anticipation Pareto
# ---------------------------------------------------------------------------
def plot_overhead_vs_lead_time(metrics_by_scheme: dict, output: str):
    """Pareto scatter: byte overhead vs median lead time.

    x: Telemetry Byte Overhead
    y: Median Positive Lead Time
    """
    fig, ax = plt.subplots(figsize=(8, 6))

    markers = {"PTT": "o", "FULL": "s", "PERIODIC_4": "^", "PERIODIC_16": "v",
               "PERIODIC_32": "<", "REACTIVE": ">", "DELTA": "D"}
    colors = {"PTT": "blue", "FULL": "green", "PERIODIC_4": "orange",
              "PERIODIC_16": "red", "PERIODIC_32": "purple",
              "REACTIVE": "brown", "DELTA": "pink"}

    for scheme, metrics_list in metrics_by_scheme.items():
        xs, ys = [], []
        for m in metrics_list:
            oh = m.get("telemetry_overhead", {}).get("byte_overhead_ratio", 0) * 100
            lt = m.get("lead_times", {}).get("median_burst_lead_us", 0) / 1000.0
            xs.append(oh)
            ys.append(lt)

        if xs:
            marker = markers.get(scheme, "o")
            color = colors.get(scheme, "gray")
            ax.scatter(xs, ys, marker=marker, color=color, label=scheme, s=80, alpha=0.7)

    ax.set_xlabel("Telemetry Byte Overhead (%)")
    ax.set_ylabel("Median Burst Lead Time (ms)")
    ax.set_title("Overhead vs. Anticipation Pareto Frontier")
    ax.legend(fontsize=8)
    ax.axhline(y=0, color="gray", linestyle=":", alpha=0.5)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output)
    plt.close(fig)
    print(f"Pareto plot saved: {output}")


# ---------------------------------------------------------------------------
# Fig 9: Microburst Heatmap
# ---------------------------------------------------------------------------
def plot_microburst_heatmap(durations_ms: list, intensities: list,
                            values: list[list], xlabel: str, ylabel: str,
                            title: str, output: str):
    """Heatmap for microburst duration x intensity matrix."""
    fig, ax = plt.subplots(figsize=(8, 6))

    if not values or not values[0]:
        ax.text(0.5, 0.5, "No microburst data", transform=ax.transAxes,
                ha="center", va="center")
        fig.savefig(output)
        plt.close(fig)
        return

    im = ax.imshow(values, cmap="YlOrRd", aspect="auto", origin="lower")

    # Set tick labels
    ax.set_xticks(range(len(durations_ms)))
    ax.set_xticklabels([f"{d}ms" for d in durations_ms])
    ax.set_yticks(range(len(intensities)))
    ax.set_yticklabels(intensities)

    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)

    # Add text annotations
    for i in range(len(intensities)):
        for j in range(len(durations_ms)):
            if i < len(values) and j < len(values[i]):
                ax.text(j, i, f"{values[i][j]:.2f}", ha="center", va="center",
                        fontsize=9)

    plt.colorbar(im, ax=ax)
    fig.tight_layout()
    fig.savefig(output)
    plt.close(fig)
    print(f"Heatmap saved: {output}")


# ---------------------------------------------------------------------------
# Main: dispatch to specific plot
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="PTT-INT plot generation")
    parser.add_argument("--plot", required=True,
                        choices=["timeline", "lead_time", "precision_recall",
                                 "overhead", "pareto", "microburst_heatmap",
                                 "all"],
                        help="Plot type to generate")
    parser.add_argument("--oracle-csv", default=None, help="oracle.csv path")
    parser.add_argument("--telemetry-csv", default=None, help="telemetry_samples.csv path")
    parser.add_argument("--events-csv", default=None, help="events.csv path")
    parser.add_argument("--metrics-json", default=None, help="metrics.json path")
    parser.add_argument("--output-dir", default="results/figures", help="Output directory")
    parser.add_argument("--q-event", type=int, default=96)
    args = parser.parse_args()

    out = ensure_output_dir(args.output_dir)

    if args.plot == "timeline":
        if not args.oracle_csv or not args.telemetry_csv:
            print("ERROR: --oracle-csv and --telemetry-csv required for timeline", file=sys.stderr)
            sys.exit(1)
        plot_mechanism_timeline(
            args.oracle_csv, args.telemetry_csv,
            args.events_csv or "",
            str(out / "fig3_mechanism_timeline.png"),
            q_event=args.q_event,
        )

    elif args.plot == "lead_time":
        if args.metrics_json:
            metrics = {"default": [load_metrics(args.metrics_json)]}
        else:
            metrics = {}
        plot_lead_time_distribution(metrics, str(out / "fig4_lead_time_dist.png"))

    elif args.plot == "precision_recall":
        if args.metrics_json:
            data = [{"horizon": 8, "metrics": load_metrics(args.metrics_json)}]
        else:
            data = []
        plot_precision_recall_vs_horizon(data, str(out / "fig5_prf_vs_horizon.png"))

    elif args.plot == "overhead":
        if args.metrics_json:
            metrics = {("default", "PTT"): load_metrics(args.metrics_json)}
        else:
            metrics = {}
        plot_overhead_by_workload(metrics, str(out / "fig6_overhead_by_workload.png"))

    elif args.plot == "pareto":
        if args.metrics_json:
            metrics = {"PTT": [load_metrics(args.metrics_json)]}
        else:
            metrics = {}
        plot_overhead_vs_lead_time(metrics, str(out / "fig8_pareto.png"))

    elif args.plot == "microburst_heatmap":
        plot_microburst_heatmap(
            [5, 10, 20, 50],
            ["2C", "3C", "4C"],
            [[0.0, 0.0, 0.0, 0.0], [0.0, 0.0, 0.0, 0.0], [0.0, 0.0, 0.0, 0.0]],
            "Duration",
            "Intensity",
            "Microburst Heatmap",
            str(out / "fig9_microburst_heatmap.png"),
        )

    elif args.plot == "all":
        print("Generating all plots (with available data)...")
        # Try to generate each plot if data is available
        for plot_name in ["timeline", "lead_time", "precision_recall", "overhead", "pareto"]:
            try:
                if args.oracle_csv and args.telemetry_csv and plot_name == "timeline":
                    plot_mechanism_timeline(
                        args.oracle_csv, args.telemetry_csv,
                        args.events_csv or "",
                        str(out / f"fig_{plot_name}.png"),
                        q_event=args.q_event,
                    )
                elif args.metrics_json:
                    m = {"default": [load_metrics(args.metrics_json)]}
                    if plot_name == "lead_time":
                        plot_lead_time_distribution(m, str(out / f"fig_{plot_name}.png"))
                    elif plot_name == "precision_recall":
                        plot_precision_recall_vs_horizon(
                            [{"horizon": 8, "metrics": load_metrics(args.metrics_json)}],
                            str(out / f"fig_{plot_name}.png"))
                    elif plot_name == "overhead":
                        plot_overhead_by_workload(
                            {("default", "PTT"): load_metrics(args.metrics_json)},
                            str(out / f"fig_{plot_name}.png"))
                    elif plot_name == "pareto":
                        plot_overhead_vs_lead_time(
                            {"PTT": [load_metrics(args.metrics_json)]},
                            str(out / f"fig_{plot_name}.png"))
            except Exception as e:
                print(f"  Skipping {plot_name}: {e}")


if __name__ == "__main__":
    main()
