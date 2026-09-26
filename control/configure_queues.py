#!/usr/bin/env python3
"""Set BMv2 queue capacity (packets) and optional service rate (packets/s)."""
import argparse
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from control.configure_switch import run_cli, valid_port


def configure_queues(thrift_port, queue_depth_packets=128, queue_rate_pps=None, port_indices=None):
    if type(queue_depth_packets) is not int or not 1 <= queue_depth_packets <= 0x7FFFF:
        raise ValueError("queue capacity must be in [1, 524287]")
    if queue_rate_pps is not None and (type(queue_rate_pps) is not int or not 0 <= queue_rate_pps <= 0x7FFFFFFF):
        raise ValueError("queue rate must be in [0, 2147483647]; zero means unlimited")
    ports = [""] if port_indices is None else [f" {valid_port(p)}" for p in port_indices]
    commands = []
    for suffix in ports:
        commands.append(f"set_queue_depth {queue_depth_packets}{suffix}")
        if queue_rate_pps is not None:
            commands.append(f"set_queue_rate {queue_rate_pps}{suffix}")
    return run_cli(thrift_port, commands) if commands else ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--thrift-port", type=int, default=9090)
    parser.add_argument("--queue-depth", type=int, default=128)
    parser.add_argument("--queue-rate", type=int)
    parser.add_argument("--ports", help="comma-separated egress ports; omitted means all ports")
    args = parser.parse_args()
    try:
        ports = [int(p) for p in args.ports.split(",")] if args.ports is not None else None
        configure_queues(args.thrift_port, args.queue_depth, args.queue_rate, ports)
    except (ValueError, RuntimeError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
