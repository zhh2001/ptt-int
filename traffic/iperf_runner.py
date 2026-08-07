#!/usr/bin/env python3
"""Traffic generation using iperf3 for PTT-INT experiments.

Supports stable, ramp, step, microburst, periodic on/off, and mixed workloads.
"""

import subprocess
import sys
import time
import json
import argparse
from pathlib import Path
from typing import Optional


def run_iperf_server(host: str, port: int = 5201, duration: int = 30) -> subprocess.Popen:
    """Start iperf3 server on a Mininet host.

    Args:
        host: Mininet host name or IP.
        port: Server port.
        duration: Server duration in seconds.

    Returns:
        Popen process for the server.
    """
    cmd = f"iperf3 -s -p {port} -1"
    # In Mininet, we run commands on hosts via `h1 cmd`
    # This is a utility; actual invocation uses Mininet API
    return subprocess.Popen(
        cmd.split(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def run_iperf_client(
    host: str,
    server_ip: str,
    port: int = 5201,
    duration: int = 30,
    bandwidth: str = "10M",
    udp: bool = True,
    packet_size: int = 1000,
    extra_args: list[str] | None = None,
) -> subprocess.Popen:
    """Start iperf3 client.

    Args:
        host: Mininet host name.
        server_ip: Destination IP.
        port: Server port.
        duration: Test duration in seconds.
        bandwidth: Target bandwidth (e.g., "10M", "1M", "100M").
        udp: Use UDP.
        packet_size: Packet size in bytes (UDP payload).
        extra_args: Additional iperf3 arguments.

    Returns:
        Popen process.
    """
    cmd = [
        "iperf3", "-c", server_ip,
        "-p", str(port),
        "-t", str(duration),
        "-b", bandwidth,
        "-l", str(packet_size),
    ]
    if udp:
        cmd.append("-u")

    if extra_args:
        cmd.extend(extra_args)

    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class TrafficSchedule:
    """Defines a traffic schedule for an experiment run."""

    def __init__(self, seed: int = 1):
        self.seed = seed
        self.entries = []

    def add_stable(self, start_s: float, duration_s: float, bandwidth: str,
                   server_ip: str, host: str = "h1", port: int = 5201):
        """Add a stable-rate flow."""
        self.entries.append({
            "type": "stable",
            "start_s": start_s,
            "duration_s": duration_s,
            "bandwidth": bandwidth,
            "server_ip": server_ip,
            "host": host,
            "port": port,
        })

    def add_ramp(self, start_s: float, duration_s: float,
                 bw_start: str, bw_end: str, steps: int,
                 server_ip: str, host: str = "h1", port: int = 5201):
        """Add a ramping flow (increasing bandwidth over time)."""
        self.entries.append({
            "type": "ramp",
            "start_s": start_s,
            "duration_s": duration_s,
            "bw_start": bw_start,
            "bw_end": bw_end,
            "steps": steps,
            "server_ip": server_ip,
            "host": host,
            "port": port,
        })

    def add_step(self, start_s: float, bw_before: str, bw_after: str,
                 switch_s: float, duration_s: float,
                 server_ip: str, host: str = "h1", port: int = 5201):
        """Add a step-change flow."""
        self.entries.append({
            "type": "step",
            "start_s": start_s,
            "bw_before": bw_before,
            "bw_after": bw_after,
            "switch_s": switch_s,
            "duration_s": duration_s,
            "server_ip": server_ip,
            "host": host,
            "port": port,
        })

    def add_microburst(self, start_s: float, burst_bw: str,
                       burst_duration_ms: int, bg_bw: str,
                       total_duration_s: float,
                       server_ip: str, host: str = "h1", port: int = 5201):
        """Add a microburst flow."""
        self.entries.append({
            "type": "microburst",
            "start_s": start_s,
            "burst_bw": burst_bw,
            "burst_duration_ms": burst_duration_ms,
            "bg_bw": bg_bw,
            "total_duration_s": total_duration_s,
            "server_ip": server_ip,
            "host": host,
            "port": port,
        })

    def save(self, output_path: str):
        """Save schedule to JSON."""
        with open(output_path, "w") as f:
            json.dump({
                "seed": self.seed,
                "entries": self.entries,
            }, f, indent=2)
        print(f"Traffic schedule saved: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Traffic schedule generator")
    parser.add_argument("--output", default="traffic_schedule.json")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    schedule = TrafficSchedule(seed=args.seed)
    schedule.add_stable(0, 30, "8M", "10.0.0.2")
    schedule.save(args.output)


if __name__ == "__main__":
    main()
