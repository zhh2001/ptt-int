#!/usr/bin/env python3
"""Oracle event detection from oracle.csv.

Based on DESIGN.md Section 15.1:
  - Congestion event starts when q >= Q_EVENT
  - Event ends when q < Q_RELEASE
  - New event can't start until release is observed
"""

import sys
import csv
import argparse
from pathlib import Path
from dataclasses import dataclass, field

EVENTS_CSV_HEADER = [
    "run_id",
    "scheme",
    "seed",
    "event_id",
    "switch_id",
    "port",
    "start_ts_us",
    "end_ts_us",
    "duration_us",
    "peak_q",
    "peak_q_ts_us",
]


@dataclass
class CongestionEvent:
    event_id: int
    switch_id: int
    port: int
    start_ts_us: int
    end_ts_us: int
    peak_q: int = 0
    peak_q_ts_us: int = 0

    @property
    def duration_us(self) -> int:
        return self.end_ts_us - self.start_ts_us


def detect_events(
    oracle_csv: str,
    q_event: int = 96,
    q_release: int = 64,
) -> list[CongestionEvent]:
    """Detect congestion events from oracle CSV.

    An event starts when q >= Q_EVENT and ends when q < Q_RELEASE.
    New events can only begin after release is observed.
    """
    rows = []
    with open(oracle_csv) as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    if not rows:
        return []

    events = []
    in_event = False
    current_event = None
    event_counter = 0

    # Group by (switch_id, port) to handle per-port events
    # First collect all ports
    ports = {}
    for row in rows:
        key = (int(row["switch_id"]), int(row["port"]))
        if key not in ports:
            ports[key] = []
        ports[key].append(row)

    for (sw_id, port), port_rows in sorted(ports.items()):
        in_event = False
        for row in port_rows:
            q = int(row["q"])
            ts = int(row["ts_us"])

            if not in_event and q >= q_event:
                # Event start
                in_event = True
                event_counter += 1
                current_event = CongestionEvent(
                    event_id=event_counter,
                    switch_id=sw_id,
                    port=port,
                    start_ts_us=ts,
                    end_ts_us=ts,
                    peak_q=q,
                    peak_q_ts_us=ts,
                )
                events.append(current_event)
            elif in_event:
                # Track peak
                if q > current_event.peak_q:
                    current_event.peak_q = q
                    current_event.peak_q_ts_us = ts

                # Update end time
                current_event.end_ts_us = ts

                # Check for release
                if q < q_release:
                    in_event = False

    return events


def write_events_csv(events: list[CongestionEvent], output_path: str,
                     run_id: str = "", scheme: str = "", seed: int = 0):
    """Write events to CSV."""
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=EVENTS_CSV_HEADER)
        writer.writeheader()
        for evt in events:
            writer.writerow({
                "run_id": run_id,
                "scheme": scheme,
                "seed": seed,
                "event_id": evt.event_id,
                "switch_id": evt.switch_id,
                "port": evt.port,
                "start_ts_us": evt.start_ts_us,
                "end_ts_us": evt.end_ts_us,
                "duration_us": evt.duration_us,
                "peak_q": evt.peak_q,
                "peak_q_ts_us": evt.peak_q_ts_us,
            })


def main():
    parser = argparse.ArgumentParser(description="Detect congestion events")
    parser.add_argument("--oracle-csv", required=True, help="Oracle CSV path")
    parser.add_argument("--output", required=True, help="Output events CSV")
    parser.add_argument("--q-event", type=int, default=96)
    parser.add_argument("--q-release", type=int, default=64)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--scheme", default="")
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    events = detect_events(
        oracle_csv=args.oracle_csv,
        q_event=args.q_event,
        q_release=args.q_release,
    )
    write_events_csv(events, args.output, args.run_id, args.scheme, args.seed)
    print(f"Detected {len(events)} events")


if __name__ == "__main__":
    main()
