#!/usr/bin/env python3
"""Parse BMv2 switch log to extract PTT_ORACLE lines.

Reads a BMv2 log file (from --log-file or --log-console), extracts
PTT_ORACLE log_msg lines, and outputs oracle.csv.
"""

import sys
import re
import csv
import argparse
from pathlib import Path

ORACLE_CSV_HEADER = [
    "run_id",
    "scheme",
    "seed",
    "switch_id",
    "port",
    "ts_us",
    "q",
    "trend",
    "q_pred_near",
    "q_pred_far",
    "state",
    "target",
]

# Regex for PTT_ORACLE log_msg output
# Format: PTT_ORACLE sw={} port={} ts={} q={} trend={} qn={} qf={} state={} target={}
ORACLE_PATTERN = re.compile(
    r"PTT_ORACLE\s+"
    r"sw=(\d+)\s+"
    r"port=(\d+)\s+"
    r"ts=(\d+)\s+"
    r"q=(\d+)\s+"
    r"trend=(\d+)\s+"
    r"qn=(\d+)\s+"
    r"qf=(\d+)\s+"
    r"state=(\d+)\s+"
    r"target=(\d+)"
)


def parse_bmv2_log(
    log_path: str,
    output_path: str,
    run_id: str = "unknown",
    scheme: str = "unknown",
    seed: int = 0,
) -> int:
    """Parse BMv2 log file and extract oracle entries.

    Returns:
        Number of oracle entries found.
    """
    try:
        with open(log_path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"ERROR: log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    rows = []
    for line in lines:
        match = ORACLE_PATTERN.search(line)
        if not match:
            continue

        row = {
            "run_id": run_id,
            "scheme": scheme,
            "seed": seed,
            "switch_id": int(match.group(1)),
            "port": int(match.group(2)),
            "ts_us": int(match.group(3)),
            "q": int(match.group(4)),
            "trend": int(match.group(5)),
            "q_pred_near": int(match.group(6)),
            "q_pred_far": int(match.group(7)),
            "state": int(match.group(8)),
            "target": int(match.group(9)),
        }
        rows.append(row)

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=ORACLE_CSV_HEADER)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Extracted {len(rows)} oracle entries from {log_path}")
    return len(rows)


def main():
    parser = argparse.ArgumentParser(
        description="Parse BMv2 log to oracle CSV")
    parser.add_argument("--log", required=True, help="BMv2 log file path")
    parser.add_argument("--output", required=True, help="Output CSV file path")
    parser.add_argument("--run-id", default="unknown", help="Run identifier")
    parser.add_argument("--scheme", default="unknown", help="Scheme name")
    parser.add_argument("--seed", type=int, default=0, help="Experiment seed")
    args = parser.parse_args()

    parse_bmv2_log(
        log_path=args.log,
        output_path=args.output,
        run_id=args.run_id,
        scheme=args.scheme,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
