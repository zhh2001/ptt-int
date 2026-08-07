#!/usr/bin/env python3
"""Parse captured pcap to extract PTT-INT telemetry samples.

Reads a pcap file, dissects PTT headers, and outputs telemetry_samples.csv.

Usage:
    python collector/parse_pcap.py --pcap capture.pcap --output telemetry_samples.csv
"""

import sys
import csv
import argparse
from pathlib import Path
from datetime import datetime

from scapy.all import rdpcap, IP, UDP, Raw
from scapy.packet import Raw

# Import local header definitions
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from collector.ptt_headers import (
    register_ptt_layers,
    PTTShim,
    PTTHop,
    STATE_NAMES,
    REASON_NAMES,
)

TELEMETRY_CSV_HEADER = [
    "run_id",
    "scheme",
    "seed",
    "recv_ts",
    "src_ip",
    "dst_ip",
    "packet_num",
    "switch_id",
    "egress_port",
    "state",
    "reason",
    "qdepth",
    "q_pred_far",
    "hop_ts_us",
    "hop_index",
    "total_hops",
    "shim_magic",
    "original_dport",
]


def parse_pcap_to_csv(
    pcap_path: str,
    output_path: str,
    run_id: str = "unknown",
    scheme: str = "unknown",
    seed: int = 0,
    int_port: int = 32768,
) -> tuple[int, int]:
    """Parse a pcap file and extract PTT telemetry samples.

    Returns:
        (total_packets, telemetry_packets): Count of all packets and INT packets.
    """
    register_ptt_layers(int_port)

    try:
        packets = rdpcap(pcap_path)
    except FileNotFoundError:
        print(f"ERROR: pcap file not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to read pcap {pcap_path}: {e}", file=sys.stderr)
        sys.exit(1)

    total_packets = 0
    telemetry_packets = 0
    rows = []

    for pkt_num, pkt in enumerate(packets, start=1):
        total_packets += 1

        if not (IP in pkt and UDP in pkt):
            continue

        udp = pkt[UDP]
        ip = pkt[IP]

        # Check if this is an INT packet
        if udp.dport != int_port or not (PTTShim in pkt):
            continue

        telemetry_packets += 1

        shim = pkt[PTTShim]
        recv_ts = float(pkt.time)

        # Extract hop records
        hops = []
        layer = pkt[PTTShim]
        while True:
            layer = layer.payload
            if isinstance(layer, PTTHop):
                hops.append(layer)
            else:
                break

        total_hops = len(hops)

        for hop_idx, hop in enumerate(hops):
            row = {
                "run_id": run_id,
                "scheme": scheme,
                "seed": seed,
                "recv_ts": f"{recv_ts:.6f}",
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "packet_num": pkt_num,
                "switch_id": hop.switch_id,
                "egress_port": hop.egress_port,
                "state": STATE_NAMES.get(hop.state, str(hop.state)),
                "reason": REASON_NAMES.get(hop.reason, str(hop.reason)),
                "qdepth": hop.qdepth,
                "q_pred_far": hop.q_pred_far,
                "hop_ts_us": hop.timestamp_low,
                "hop_index": hop_idx,
                "total_hops": total_hops,
                "shim_magic": f"0x{shim.magic:04x}",
                "original_dport": shim.original_udp_dport,
            }
            rows.append(row)

    # Write CSV
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=TELEMETRY_CSV_HEADER)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Parsed {total_packets} packets, {telemetry_packets} INT packets, "
          f"{len(rows)} hop records")
    return total_packets, telemetry_packets


def main():
    parser = argparse.ArgumentParser(description="Parse pcap to PTT telemetry CSV")
    parser.add_argument("--pcap", required=True, help="Input pcap file path")
    parser.add_argument("--output", required=True, help="Output CSV file path")
    parser.add_argument("--run-id", default="unknown", help="Run identifier")
    parser.add_argument("--scheme", default="unknown", help="Scheme name")
    parser.add_argument("--seed", type=int, default=0, help="Experiment seed")
    parser.add_argument("--int-port", type=int, default=32768,
                        help="INT UDP port (default: 32768)")
    args = parser.parse_args()

    parse_pcap_to_csv(
        pcap_path=args.pcap,
        output_path=args.output,
        run_id=args.run_id,
        scheme=args.scheme,
        seed=args.seed,
        int_port=args.int_port,
    )


if __name__ == "__main__":
    main()
