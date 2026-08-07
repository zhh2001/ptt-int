#!/usr/bin/env python3
"""Configure BMv2 switch tables for PTT-INT operation.

Sets up:
- LPM forwarding table entries
- Scheme mode register
- Switch ID register
"""

import subprocess
import sys
import argparse
import json


def run_cli(thrift_port: int, commands: list[str], timeout: float = 10.0) -> str:
    """Execute commands via simple_switch_CLI and return output."""
    input_str = "\n".join(commands) + "\n"
    result = subprocess.run(
        [
            "simple_switch_CLI",
            "--thrift-port", str(thrift_port),
            "--json", "p4src/ptt_int.json",
        ],
        input=input_str,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        print(f"CLI stderr: {result.stderr}", file=sys.stderr)
        raise RuntimeError(f"simple_switch_CLI failed: {result.stderr}")
    return result.stdout


def configure_forwarding(thrift_port: int, routes: list[dict]):
    """Install IPv4 LPM forwarding entries.

    Args:
        thrift_port: Thrift port for the switch.
        routes: List of dicts with keys 'dst_ip' (prefix), 'port' (int).
    """
    commands = []
    for route in routes:
        dst = route["dst_ip"]
        port = route["port"]
        # Format: table_add <table_name> <action_name> <match_key> => <action_params>
        commands.append(
            f"table_add ipv4_lpm forward {dst} => {port}"
        )
    if commands:
        output = run_cli(thrift_port, commands)
        print(f"Installed {len(routes)} forwarding rules")
        return output


def configure_scheme(thrift_port: int, scheme_mode: int):
    """Set the telemetry scheme mode register.

    Args:
        thrift_port: Thrift port for the switch.
        scheme_mode: 0=FULL, 1=PERIODIC_4, 2=PERIODIC_16, 3=PERIODIC_32,
                     4=REACTIVE, 5=DELTA, 6=PTT
    """
    commands = [
        f"register_write scheme_mode_reg 0 {scheme_mode}",
    ]
    output = run_cli(thrift_port, commands)
    print(f"Set scheme_mode = {scheme_mode}")


def configure_switch_id(thrift_port: int, switch_id: int):
    """Set the switch ID register.

    Args:
        thrift_port: Thrift port for the switch.
        switch_id: Switch identifier (1-4095).
    """
    commands = [
        f"register_write switch_id_reg 0 {switch_id}",
    ]
    output = run_cli(thrift_port, commands)
    print(f"Set switch_id = {switch_id}")


def main():
    parser = argparse.ArgumentParser(description="Configure PTT-INT switch tables")
    parser.add_argument("--thrift-port", type=int, default=9090,
                        help="Thrift server port (default: 9090)")
    parser.add_argument("--scheme", type=int, default=6,
                        help="Scheme mode: 0=FULL 1=PERIODIC_4 2=PERIODIC_16 "
                             "3=PERIODIC_32 4=REACTIVE 5=DELTA 6=PTT")
    parser.add_argument("--switch-id", type=int, default=1,
                        help="Switch ID (default: 1)")
    parser.add_argument("--routes", type=str, default=None,
                        help="JSON string of route list [{dst_ip, port}, ...]")
    args = parser.parse_args()

    try:
        configure_switch_id(args.thrift_port, args.switch_id)
        configure_scheme(args.thrift_port, args.scheme)

        if args.routes:
            routes = json.loads(args.routes)
            configure_forwarding(args.thrift_port, routes)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
