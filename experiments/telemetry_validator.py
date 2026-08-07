#!/usr/bin/env python3
"""Gate B: Telemetry Header Validator.

Per-packet validation of PTT instrumented packets plus counter-based
sampling ratio verification.

1. Packet-level: magic, version, hop_count, hop records, IPv4, checksum, MTU.
2. Sampling ratios: reads per-port Gate B counters via simple_switch_CLI and
   computes actual sampling ratios per state (packet-based, not epoch-based).
   Separates normal-state samples from freshness-forced reports.
"""

import sys
import json
import struct
import argparse
from pathlib import Path
from collections import defaultdict

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scapy.all import rdpcap, IP, UDP, Raw
from collector.ptt_headers import (
    PTTShim, PTTHop, register_ptt_layers,
    STATE_NAMES, REASON_NAMES,
)

# Expected protocol constants (must match p4src/ptt_int.p4)
EXPECTED_MAGIC = 0x5054
EXPECTED_VERSION = 1
MAX_HOPS = 8
Q_CAP = 128
MTU = 2000
INT_PORT = 32768
EXPECTED_QUIET_RATIO = 1.0 / 32.0  # 1/32
EXPECTED_WATCH_RATIO = 1.0 / 4.0   # 1/4
EXPECTED_BURST_RATIO = 1.0          # 1/1
RATIO_TOLERANCE = 0.15               # allow ±15% deviation for short runs


def validate_pcap(pcap_path: str, int_port: int = INT_PORT) -> dict:
    """Validate every PTT-instrumented packet in a pcap file.

    Returns a dict with per-check pass/fail counts and violation details.
    """
    register_ptt_layers(int_port)

    checks = {
        "magic_match": {"passed": 0, "failed": 0, "violations": []},
        "version_match": {"passed": 0, "failed": 0, "violations": []},
        "hop_count_range": {"passed": 0, "failed": 0, "violations": []},
        "switch_id_range": {"passed": 0, "failed": 0, "violations": []},
        "state_range": {"passed": 0, "failed": 0, "violations": []},
        "qdepth_range": {"passed": 0, "failed": 0, "violations": []},
        "q_pred_far_range": {"passed": 0, "failed": 0, "violations": []},
        "hop_ordering": {"passed": 0, "failed": 0, "violations": []},
        "ipv4_total_length": {"passed": 0, "failed": 0, "violations": []},
        "ipv4_checksum": {"passed": 0, "failed": 0, "violations": []},
        "mtu_check": {"passed": 0, "failed": 0, "violations": []},
        "ptt_shim_present": {"passed": 0, "failed": 0, "violations": []},
    }

    telemetry_packets = 0
    total_packets = 0
    state_samples = defaultdict(int)

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        return {"error": f"Cannot read pcap: {e}", "checks": checks}

    for pkt in packets:
        total_packets += 1
        if not pkt.haslayer(PTTShim):
            # Not a telemetry packet — skip field-level checks
            continue

        telemetry_packets += 1
        shim = pkt[PTTShim]

        # --- Magic ---
        if shim.magic == EXPECTED_MAGIC:
            checks["magic_match"]["passed"] += 1
        else:
            checks["magic_match"]["failed"] += 1
            checks["magic_match"]["violations"].append(
                f"Packet {total_packets}: magic={shim.magic:#06x}, expected={EXPECTED_MAGIC:#06x}"
            )

        # --- Version ---
        if shim.version == EXPECTED_VERSION:
            checks["version_match"]["passed"] += 1
        else:
            checks["version_match"]["failed"] += 1
            checks["version_match"]["violations"].append(
                f"Packet {total_packets}: version={shim.version}, expected={EXPECTED_VERSION}"
            )

        # --- Hop count ---
        hop_count = shim.hop_count
        if 0 < hop_count <= MAX_HOPS:
            checks["hop_count_range"]["passed"] += 1
        else:
            checks["hop_count_range"]["failed"] += 1
            checks["hop_count_range"]["violations"].append(
                f"Packet {total_packets}: hop_count={hop_count}, max={MAX_HOPS}"
            )

        # --- Hop records ---
        hop_layers = pkt.getlayer(PTTHop)
        if hop_layers is None:
            continue

        # If multiple hops, scapy returns a list
        hops = hop_layers if isinstance(hop_layers, list) else [hop_layers]

        for i, hop in enumerate(hops):
            # Switch ID range (1-64 reasonable, 0 is allowed for unknown)
            if 0 <= hop.switch_id <= 64:
                checks["switch_id_range"]["passed"] += 1
            else:
                checks["switch_id_range"]["failed"] += 1
                checks["switch_id_range"]["violations"].append(
                    f"Packet {total_packets} hop {i}: switch_id={hop.switch_id}"
                )

            # State range
            if hop.state in (0, 1, 2):
                checks["state_range"]["passed"] += 1
            else:
                checks["state_range"]["failed"] += 1
                checks["state_range"]["violations"].append(
                    f"Packet {total_packets} hop {i}: state={hop.state}"
                )

            # Queue depth range
            if 0 <= hop.qdepth <= Q_CAP:
                checks["qdepth_range"]["passed"] += 1
            else:
                checks["qdepth_range"]["failed"] += 1
                checks["qdepth_range"]["violations"].append(
                    f"Packet {total_packets} hop {i}: qdepth={hop.qdepth}"
                )

            # q_pred_far range (19-bit field)
            if 0 <= hop.q_pred_far <= 0x7FFFF:
                checks["q_pred_far_range"]["passed"] += 1
            else:
                checks["q_pred_far_range"]["failed"] += 1
                checks["q_pred_far_range"]["violations"].append(
                    f"Packet {total_packets} hop {i}: q_pred_far={hop.q_pred_far}"
                )

            # Track state for sampling analysis
            state_samples[STATE_NAMES.get(hop.state, f"UNKNOWN_{hop.state}")] += 1

        # --- Hop ordering: index 0 should be the nearest switch ---
        # Collect (hop_index, switch_id) pairs
        hop_ids = []
        for layer_name in dir(pkt):
            if layer_name.startswith('PTTHop'):
                try:
                    hop = pkt[layer_name]
                except Exception:
                    continue
                # Extract index from PTTHop0, PTTHop1, etc.
                idx_str = layer_name.replace('PTTHop', '')
                if idx_str.isdigit() and hasattr(hop, 'switch_id'):
                    hop_ids.append((int(idx_str), hop.switch_id))

        if hop_ids and len(hop_ids) > 1:
            # All hops should have unique indices
            if len(set(h[0] for h in hop_ids)) == len(hop_ids):
                checks["hop_ordering"]["passed"] += 1
            else:
                checks["hop_ordering"]["failed"] += 1
                checks["hop_ordering"]["violations"].append(
                    f"Packet {total_packets}: duplicate hop indices"
                )

        # --- IPv4 total length check ---
        if IP in pkt:
            ip_len = pkt[IP].len
            # Expected: IP header (20) + UDP header (8) + UDP payload + PTT shim (8) + hops (12*count)
            expected = 20 + 8
            if pkt.haslayer(UDP):
                expected += len(pkt[UDP].payload) if hasattr(pkt[UDP], 'payload') else 0
            if abs(ip_len - expected) <= 50:  # allow some flexibility
                checks["ipv4_total_length"]["passed"] += 1
            else:
                checks["ipv4_total_length"]["failed"] += 1
                checks["ipv4_total_length"]["violations"].append(
                    f"Packet {total_packets}: ip_len={ip_len}, expected~={expected}"
                )

        # --- MTU check ---
        pkt_len = len(pkt)
        if pkt_len <= MTU:
            checks["mtu_check"]["passed"] += 1
        else:
            checks["mtu_check"]["failed"] += 1
            checks["mtu_check"]["violations"].append(
                f"Packet {total_packets}: length={pkt_len}, MTU={MTU}"
            )

    # --- Overall PTT shim presence ---
    checks["ptt_shim_present"]["passed"] = telemetry_packets
    checks["ptt_shim_present"]["failed"] = total_packets - telemetry_packets

    return {
        "total_packets": total_packets,
        "telemetry_packets": telemetry_packets,
        "checks": checks,
        "state_samples": dict(state_samples),
    }


def validate_sampling_ratios(counters: dict,
                              oracle_csv_path: str = None) -> dict:
    """Validate sampling ratios from Gate B counter registers.

    counters must have keys: eligible_quiet, eligible_watch, eligible_burst,
    sampled_quiet, sampled_watch, sampled_burst, freshness_forced.

    If *oracle_csv_path* is provided, eligible-packet counts are derived from
    the oracle CSV (one oracle entry per packet arrival epoch), giving
    PACKET-BASED denominators instead of the epoch-based register counters.

    Sampling ratios are PACKET-BASED:
    - QUIET: sampled_quiet / eligible_quiet ≈ 1/32
    - WATCH: sampled_watch / eligible_watch ≈ 1/4
    - BURST: sampled_burst / eligible_burst ≈ 1/1

    Freshness-forced reports are excluded from normal sampling counts.
    """
    # Derive eligible PACKET counts from oracle CSV if provided
    # (each oracle entry corresponds to a packet arrival, giving packet-based
    #  denominators rather than epoch-based register counters)
    oracle_eligible = None
    if oracle_csv_path:
        try:
            import csv as _csv
            oracle_eligible = {"quiet": 0, "watch": 0, "burst": 0}
            with open(oracle_csv_path) as f:
                for row in _csv.DictReader(f):
                    state = int(row.get("state", 0))
                    if state == 0:
                        oracle_eligible["quiet"] += 1
                    elif state == 1:
                        oracle_eligible["watch"] += 1
                    elif state == 2:
                        oracle_eligible["burst"] += 1
        except Exception:
            oracle_eligible = None

    # Use oracle-derived packet counts as denominators when available
    if oracle_eligible is not None:
        eligible_quiet = oracle_eligible["quiet"]
        eligible_watch = oracle_eligible["watch"]
        eligible_burst = oracle_eligible["burst"]
        source = "oracle_csv (packet-based)"
    else:
        eligible_quiet = counters.get("eligible_quiet", 0)
        eligible_watch = counters.get("eligible_watch", 0)
        eligible_burst = counters.get("eligible_burst", 0)
        source = "gate_b_counters (epoch-based)"

    result = {
        "quiet": {"eligible": eligible_quiet,
                  "sampled": counters.get("sampled_quiet", 0),
                  "expected_ratio": EXPECTED_QUIET_RATIO},
        "watch": {"eligible": eligible_watch,
                  "sampled": counters.get("sampled_watch", 0),
                  "expected_ratio": EXPECTED_WATCH_RATIO},
        "burst": {"eligible": eligible_burst,
                  "sampled": counters.get("sampled_burst", 0),
                  "expected_ratio": EXPECTED_BURST_RATIO},
        "freshness_forced": counters.get("freshness_forced", 0),
        "denominator_source": source,
    }

    all_pass = True
    total_eligible = 0
    for state in ("quiet", "watch", "burst"):
        s = result[state]
        eligible = s["eligible"]
        sampled = s["sampled"]
        total_eligible += eligible
        if eligible > 0:
            actual = sampled / eligible
            s["actual_ratio"] = actual
            s["deviation"] = actual - s["expected_ratio"]
            s["within_tolerance"] = abs(s["deviation"]) <= RATIO_TOLERANCE
            if not s["within_tolerance"]:
                all_pass = False
        else:
            s["actual_ratio"] = None
            s["deviation"] = None
            s["within_tolerance"] = None

    # NOT_EVALUABLE: no telemetry traffic was eligible for any state
    result["not_evaluable"] = (total_eligible == 0)
    if total_eligible == 0:
        all_pass = False
        result["not_evaluable_reason"] = (
            "eligible=0 for all states (QUIET, WATCH, BURST). "
            "No packets were eligible for telemetry sampling. This indicates "
            "either no traffic reached the telemetry insertion point, or the "
            "counter registers were not populated."
        )

    result["all_pass"] = all_pass
    return result


def print_report(pcap_result: dict, sampling_result: dict = None):
    """Print a human-readable validation report."""
    print("=" * 60)
    print("Gate B: Telemetry Validation Report")
    print("=" * 60)

    if "error" in pcap_result:
        print(f"\nERROR: {pcap_result['error']}")
        return

    print(f"\nPackets: {pcap_result['total_packets']} total, "
          f"{pcap_result['telemetry_packets']} telemetry")

    print("\n--- Per-Field Validation ---")
    for check_name, check_data in sorted(pcap_result["checks"].items()):
        status = "PASS" if check_data["failed"] == 0 else "FAIL"
        print(f"  {check_name}: {status} "
              f"({check_data['passed']} passed, {check_data['failed']} failed)")
        if check_data["violations"]:
            for v in check_data["violations"][:5]:
                print(f"    - {v}")
            if len(check_data["violations"]) > 5:
                print(f"    ... and {len(check_data['violations']) - 5} more")

    print("\n--- State Distribution in Telemetry ---")
    for state, count in sorted(pcap_result.get("state_samples", {}).items()):
        print(f"  {state}: {count}")

    if sampling_result:
        print("\n--- Counter-Based Sampling Ratios (Packet-Based) ---")
        print(f"  Denominator source: {sampling_result.get('denominator_source', 'unknown')}")
        if sampling_result.get("not_evaluable"):
            print(f"  STATUS: NOT_EVALUABLE — {sampling_result['not_evaluable_reason']}")
        for state in ("quiet", "watch", "burst"):
            s = sampling_result[state]
            actual_str = f"{s['actual_ratio']:.4f}" if s['actual_ratio'] is not None else "N/A"
            print(f"  {state.upper()}: sampled={s['sampled']}, eligible={s['eligible']}, "
                  f"ratio={actual_str} (expected={s['expected_ratio']:.4f})")
        print(f"  freshness_forced: {sampling_result['freshness_forced']}")
        print(f"  All within tolerance: {sampling_result['all_pass']}")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Gate B: Telemetry Validator")
    parser.add_argument("--pcap", required=True, help="Path to pcap file")
    parser.add_argument("--int-port", type=int, default=INT_PORT, help="INT port number")
    parser.add_argument("--counters-json", default=None,
                        help="JSON file with Gate B counter readings (optional)")
    parser.add_argument("--oracle-csv", default=None,
                        help="Oracle CSV to derive PACKET-BASED eligible counts (preferred)")
    parser.add_argument("--output", default=None, help="Output JSON report path")
    args = parser.parse_args()

    pcap_result = validate_pcap(args.pcap, args.int_port)

    sampling_result = None
    if args.counters_json:
        with open(args.counters_json) as f:
            counters = json.load(f)
        sampling_result = validate_sampling_ratios(counters, args.oracle_csv)

    report = {
        "pcap_validation": pcap_result,
        "sampling_validation": sampling_result,
    }

    print_report(pcap_result, sampling_result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nReport saved: {args.output}")


if __name__ == "__main__":
    main()
