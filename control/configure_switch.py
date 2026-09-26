#!/usr/bin/env python3
"""Configure the PTT-INT switch identifier and IPv4 port-forwarding table."""
import argparse
import ipaddress
import json
import re
import subprocess


def run_cli(thrift_port, commands, timeout=10.0):
    if type(thrift_port) is not int or not 1 <= thrift_port <= 65535:
        raise ValueError("invalid Thrift port")
    result = subprocess.run(
        ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
        input="\n".join(commands) + "\n", capture_output=True, text=True, timeout=timeout,
    )
    output = result.stdout + result.stderr
    # BMv2's interactive CLI can report a command error with exit status zero.
    if result.returncode or re.search(r"\b(error|invalid|exception|failed)\b", output, re.I):
        raise RuntimeError(f"simple_switch_CLI failed:\n{output}")
    return result.stdout


def valid_port(port):
    if type(port) is not int or not 0 <= port < 511:
        raise ValueError("egress port must be in [0, 510]; 511 is the drop port")
    return port


def forwarding_commands(routes):
    commands = []
    for route in routes:
        if set(route) != {"dst_ip", "port"}:
            raise ValueError("each route requires only dst_ip and port")
        prefix = ipaddress.IPv4Network(route["dst_ip"], strict=False)
        port = valid_port(route["port"])
        commands.append(f"table_add PttIngress.ipv4_lpm PttIngress.forward {prefix} => {port}")
    return commands


def configure_forwarding(thrift_port, routes):
    commands = forwarding_commands(routes)
    return run_cli(thrift_port, commands) if commands else ""


def configure_switch_id(thrift_port, switch_id):
    if type(switch_id) is not int or not 0 <= switch_id <= 4095:
        raise ValueError("switch ID must be in [0, 4095]")
    return run_cli(thrift_port, [f"register_write switch_id_reg 0 {switch_id}"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--thrift-port", type=int, default=9090)
    parser.add_argument("--switch-id", type=int, default=1)
    parser.add_argument("--routes", default="[]", help="JSON list of {dst_ip, port}")
    args = parser.parse_args()
    try:
        commands = forwarding_commands(json.loads(args.routes))
        if not 0 <= args.switch_id <= 4095:
            raise ValueError("invalid switch ID")
        run_cli(args.thrift_port, [f"register_write switch_id_reg 0 {args.switch_id}"] + commands)
    except (ValueError, RuntimeError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
