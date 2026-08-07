#!/usr/bin/env python3
"""Run manifest: records experiment configuration and metadata.
"""

import json
import subprocess
import sys
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def get_git_commit() -> str:
    """Get current git commit hash, or 'unknown' if not in a repo."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def get_bmv2_commit() -> str:
    """Get behavioral-model commit hash."""
    try:
        result = subprocess.run(
            ["git", "-C", "/home/howard/behavioral-model", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def get_git_dirty() -> bool:
    """Check if working tree is dirty."""
    try:
        result = subprocess.run(
            ["git", "diff", "--stat"],
            capture_output=True, text=True, timeout=5,
        )
        return bool(result.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return False


def create_manifest(
    config: dict,
    run_id: str,
    scheme: str,
    seed: int,
    topology: str,
    extras: dict | None = None,
) -> dict:
    """Create a run manifest dictionary.

    Args:
        config: Resolved configuration dict.
        run_id: Unique run identifier.
        scheme: Scheme name (PTT, FULL, REACTIVE, etc.).
        seed: Experiment seed.
        topology: Topology name.
        extras: Additional metadata to include.

    Returns:
        Manifest dict ready for JSON serialization.
    """
    manifest = {
        "run_id": run_id,
        "git_commit": get_git_commit(),
        "git_dirty": get_git_dirty(),
        "bmv2_commit": get_bmv2_commit(),
        "date": datetime.now(timezone.utc).isoformat(),
        "scheme": scheme,
        "seed": seed,
        "topology": topology,
        "queue_depth": config["queue"]["capacity_packets"],
        "queue_rate": extras.get("queue_rate") if extras else None,
        "packet_size": config["packet"]["original_packet_size"],
        "epoch_us": config["predictor"]["epoch_us"],
        "h_near": config["predictor"]["near_horizon"],
        "h_far": config["predictor"]["far_horizon"],
        "q_event": config["queue"]["event_threshold_packets"],
        "q_release": config["queue"]["release_threshold_packets"],
        "ewma_alpha": f"1/{1 << config['predictor']['ewma_alpha_shift']}",
        "recovery_epochs": config["fsm"]["recovery_epochs"],
        "max_hops": config["packet"]["max_hops"],
        "int_port": config["packet"]["int_port"],
    }

    if extras:
        manifest.update(extras)

    return manifest


def save_manifest(manifest: dict, output_dir: str):
    """Save manifest to output directory as JSON."""
    out_path = Path(output_dir) / "manifest.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Manifest saved: {out_path}")


def main():
    print("Manifest module: use create_manifest() and save_manifest()")


if __name__ == "__main__":
    main()
