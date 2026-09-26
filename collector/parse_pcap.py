#!/usr/bin/env python3
"""Stream captured PTT packets to CSV; one row per actual hop record."""
import argparse
import csv
import sys
from pathlib import Path
from scapy.all import IP, UDP, PcapReader

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from collector.ptt_headers import decode_ptt, parse_state_name, parse_reason_name

TELEMETRY_CSV_HEADER = [
    "recv_ts", "src_ip", "dst_ip", "packet_num", "switch_id", "egress_port",
    "state", "reason", "qdepth", "q_pred_far", "hop_ts_low_us", "hop_index",
    "total_hops", "original_dport", "overflow",
]


def parse_pcap_to_csv(pcap_path, output_path, int_port=32768, max_hops=8):
    """Return (all packets, valid PTT packets). Malformed packets yield no rows.

    Hop index 0 is the most recent insertion. Timestamp values are low 32 bits
    of each switch's local clock, not synchronized absolute timestamps.
    """
    total = telemetry = 0
    with PcapReader(str(pcap_path)) as packets, open(output_path, "w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=TELEMETRY_CSV_HEADER)
        writer.writeheader()
        for total, pkt in enumerate(packets, 1):
            if IP not in pkt or UDP not in pkt:
                continue
            ip, udp = pkt[IP], pkt[UDP]
            if ip.version != 4 or ip.frag or int(ip.flags) & 1 or udp.dport != int_port:
                continue
            raw_ip = bytes(ip)
            header_bytes = ip.ihl * 4
            if header_bytes < 20 or ip.len > len(raw_ip) or udp.len < 8 or udp.len != ip.len - header_bytes:
                continue
            try:
                shim, hops, _ = decode_ptt(raw_ip[header_bytes + 8:ip.len], max_hops)
            except ValueError:
                continue
            telemetry += 1
            for index, hop in enumerate(hops):
                writer.writerow({
                    "recv_ts": f"{float(pkt.time):.6f}", "src_ip": ip.src,
                    "dst_ip": ip.dst, "packet_num": total,
                    "switch_id": hop.switch_id, "egress_port": hop.egress_port,
                    "state": parse_state_name(hop.state), "reason": parse_reason_name(hop.reason),
                    "qdepth": hop.qdepth, "q_pred_far": hop.q_pred_far,
                    "hop_ts_low_us": hop.timestamp_low, "hop_index": index,
                    "total_hops": shim.hop_count, "original_dport": shim.original_udp_dport,
                    "overflow": int(bool(shim.flags & 1)),
                })
    return total, telemetry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--int-port", type=int, default=32768)
    parser.add_argument("--max-hops", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.int_port <= 65535 or not 1 <= args.max_hops <= 8:
        parser.error("invalid INT port or maximum hop count")
    total, telemetry = parse_pcap_to_csv(args.pcap, args.output, args.int_port, args.max_hops)
    print(f"Parsed {total} packets, {telemetry} valid PTT packets")


if __name__ == "__main__":
    main()
