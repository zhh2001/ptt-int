#!/usr/bin/env python3
"""Thin wrapper around oracle/events.py for experiment pipeline."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from oracle.events import detect_events, write_events_csv, CongestionEvent


def detect_and_save_events(
    oracle_csv: str,
    output_path: str,
    run_id: str,
    scheme: str,
    seed: int,
    q_event: int = 96,
    q_release: int = 64,
) -> list[CongestionEvent]:
    """Detect congestion events from oracle CSV and save to file.

    Returns list of CongestionEvent objects.
    """
    events = detect_events(
        oracle_csv=oracle_csv,
        q_event=q_event,
        q_release=q_release,
    )
    write_events_csv(events, output_path, run_id, scheme, seed)
    return events
