#!/usr/bin/env python3
"""Configure BMv2 egress queue depth and rate via simple_switch_CLI.

Queue depth is in packets; rate is in packets per second.
"""

import subprocess
import sys
import time
import argparse
from pathlib import Path


def run_cli(thrift_port: int, commands: list[str], timeout: float = 10.0) -> str:
    """Execute commands via simple_switch_CLI and return output."""
    input_str = "\n".join(commands) + "\n"
    result = subprocess.run(
        [
            "simple_switch_CLI",
            "--thrift-port", str(thrift_port),
        ],
        input=input_str,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        print(f"CLI error (returncode={result.returncode}):", file=sys.stderr)
        print(f"stdout: {result.stdout}", file=sys.stderr)
        print(f"stderr: {result.stderr}", file=sys.stderr)
        raise RuntimeError(f"simple_switch_CLI failed: {result.stderr}")
    return result.stdout


def configure_queues(
    thrift_port: int,
    queue_depth_packets: int = 128,
    queue_rate_pps: int | None = None,
    port_indices: list[int] | None = None,
):
    """Set queue depth and rate on specified egress ports.

    Args:
        thrift_port: Thrift server port for the BMv2 switch.
        queue_depth_packets: Maximum queue depth in packets.
        queue_rate_pps: Service rate in packets per second (None = no rate limit).
        port_indices: List of port indices to configure (None = all).
    """
    if port_indices is None:
        port_indices = list(range(512))

    print(f"Configuring queue depth={queue_depth_packets} on thrift port {thrift_port}")
    print(f"Queue rate: {queue_rate_pps} pps")

    commands = []
    for port_idx in port_indices:
        # Set queue depth — BMv2 CLI: set_queue_depth <nb_pkts> [<port>]
        commands.append(f"set_queue_depth {queue_depth_packets} {port_idx}")

        # Set queue rate if specified
        if queue_rate_pps is not None:
            # BMv2 CLI: set_queue_rate <rate_pps> [<port>]
            commands.append(f"set_queue_rate {queue_rate_pps} {port_idx}")

    output = run_cli(thrift_port, commands)
    print(f"Configured {len(port_indices)} ports")
    return output


def main():
    parser = argparse.ArgumentParser(description="Configure BMv2 queue parameters")
    parser.add_argument("--thrift-port", type=int, default=9090,
                        help="Thrift server port (default: 9090)")
    parser.add_argument("--queue-depth", type=int, default=128,
                        help="Queue depth in packets (default: 128)")
    parser.add_argument("--queue-rate", type=int, default=None,
                        help="Queue service rate in pps (default: no limit)")
    parser.add_argument("--ports", type=str, default=None,
                        help="Comma-separated port indices (default: all)")
    args = parser.parse_args()

    port_indices = None
    if args.ports:
        port_indices = [int(p.strip()) for p in args.ports.split(",")]

    try:
        configure_queues(
            thrift_port=args.thrift_port,
            queue_depth_packets=args.queue_depth,
            queue_rate_pps=args.queue_rate,
            port_indices=port_indices,
        )
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
