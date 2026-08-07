#!/usr/bin/env python3
"""Deterministic packet-level traffic plan generators for PTT-INT experiments.

Each generator takes (seed, topology, config) and returns list[TrafficEntry].
All generators are deterministic given the same seed.

Primary host pairs:
  single_bottleneck: h1 (10.0.0.1) -> h2 (10.0.0.2)
  incast:            h2..hN -> h1 (10.0.0.1) with round-robin across senders
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class TrafficEntry:
    """A single packet in a deterministic traffic plan.

    Attributes:
        relative_time_ns: Departure time in nanoseconds from experiment start.
        src_host: Sending host name (e.g. "h1").
        dst_host: Receiving host name (e.g. "h2").
        dst_ip: Destination IP address of the packet.
        dst_port: Destination UDP port.
        flow_id: Logical flow identifier (0 for single-flow workloads).
        packet_size: UDP payload size in bytes.
        sequence_no: Per-flow, monotonic, zero-based sequence number.
    """

    relative_time_ns: int
    src_host: str
    dst_host: str
    dst_ip: str
    dst_port: int
    flow_id: int
    packet_size: int
    sequence_no: int


# Re-export so callers can do:
#   from experiments.workloads import TrafficEntry, generate_stable
# The canonical home for the class is experiments.traffic_generator; workloads.py
# defines it here as a convenience until that module is created.
try:
    from experiments.traffic_generator import TrafficEntry  # noqa: F811
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_DST_PORT: int = 65534  # DATA_PORT from config default.yaml
DEFAULT_SRC_HOST: str = "h1"
DEFAULT_DST_HOST: str = "h2"
DEFAULT_SRC_IP: str = "10.0.0.1"
DEFAULT_DST_IP: str = "10.0.0.2"
DEFAULT_BOTTLENECK_RATE: int = 100  # pps fallback when not in runtime/config

# Incast topology
INCAST_RX_HOST: str = "h1"
INCAST_RX_IP: str = "10.0.0.1"
INCAST_DST_PORT: int = 65534
DEFAULT_NUM_SENDERS: int = 4


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_SECONDS_TO_NANOS: int = 1_000_000_000
_MS_TO_SECONDS: float = 0.001


def _to_ns(t_s: float) -> int:
    """Convert fractional seconds to integer nanoseconds."""
    return int(t_s * _SECONDS_TO_NANOS)


def _resolve_bottleneck_rate(
    config: dict,
    runtime: Optional[dict] = None,
) -> int:
    """Extract bottleneck_rate_pps from runtime dict, config dict, or fallback."""
    runtime = runtime or {}
    rate = runtime.get("bottleneck_rate_pps")
    if rate is not None:
        return int(rate)
    rate = config.get("bottleneck_rate_pps")
    if rate is not None:
        return int(rate)
    return DEFAULT_BOTTLENECK_RATE


def _resolve_packet_size(config: dict) -> int:
    """Extract packet size from config."""
    return int(config["packet"]["original_packet_size"])


def _make_rng(seed: int) -> random.Random:
    """Create a deterministic random.Random instance from a seed."""
    return random.Random(seed)


def _uniform_packets(
    *,
    rate_pps: float,
    start_time_s: float,
    duration_s: float,
    src_host: str,
    dst_host: str,
    dst_ip: str,
    dst_port: int,
    flow_id: int,
    packet_size: int,
    start_seq: int = 0,
) -> List[TrafficEntry]:
    """Generate uniformly-spaced packets at a constant rate.

    Args:
        rate_pps: Packet rate in packets per second.
        start_time_s: Start time in fractional seconds.
        duration_s: Duration in seconds.
        start_seq: Starting sequence number.

    Returns:
        List of TrafficEntry objects sorted by relative_time_ns.
    """
    if rate_pps <= 0 or duration_s <= 0:
        return []

    n_packets: int = math.ceil(rate_pps * duration_s)
    if n_packets == 0:
        return []

    entries: List[TrafficEntry] = []
    for i in range(n_packets):
        # Center each packet in its interval for uniform spacing
        t_s: float = start_time_s + (i + 0.5) / n_packets * duration_s
        t_ns: int = _to_ns(t_s)
        entries.append(
            TrafficEntry(
                relative_time_ns=t_ns,
                src_host=src_host,
                dst_host=dst_host,
                dst_ip=dst_ip,
                dst_port=dst_port,
                flow_id=flow_id,
                packet_size=packet_size,
                sequence_no=start_seq + i,
            )
        )
    return entries


def _ramp_packets(
    *,
    start_rate_pps: float,
    end_rate_pps: float,
    start_time_s: float,
    duration_s: float,
    src_host: str,
    dst_host: str,
    dst_ip: str,
    dst_port: int,
    flow_id: int,
    packet_size: int,
    start_seq: int = 0,
) -> List[TrafficEntry]:
    """Generate packets for a linearly-varying rate r(t).

    Rate at time t: r(t) = r0 + (r1 - r0) * (t / D)
    Uses inverse-transform sampling on the cumulative rate function for
    deterministic, uniform-in-probability packet placement.

    Returns:
        List of TrafficEntry objects sorted by relative_time_ns.
    """
    if duration_s <= 0:
        return []

    r0: float = start_rate_pps
    r1: float = end_rate_pps

    if r0 <= 0 and r1 <= 0:
        return []

    # Total packets = integral of r(t) over [0, D]
    # Integral = (r0 + r1) / 2 * duration_s
    avg_rate: float = (r0 + r1) / 2.0
    n_packets: int = math.ceil(avg_rate * duration_s)
    if n_packets == 0:
        return []

    # Cumulative rate F(t) = r0*t + dr/(2D) * t^2
    # F(D) = (r0 + r1) * D / 2
    total_flow: float = avg_rate * duration_s
    dr: float = r1 - r0

    entries: List[TrafficEntry] = []
    for i in range(n_packets):
        target: float = (i + 0.5) * total_flow / n_packets

        if abs(dr) < 0.5:
            # Constant or near-constant rate: linear placement
            t_s: float = target / max(r0, 1e-9)
        else:
            # Solve quadratic: a*t^2 + b*t + c = 0
            # where a = dr/(2*D), b = r0, c = -target
            a: float = dr / (2.0 * duration_s)
            b: float = r0
            c: float = -target
            discriminant: float = b * b - 4.0 * a * c
            if discriminant < 0:
                discriminant = 0.0
            t_s = (-b + math.sqrt(discriminant)) / (2.0 * a)

        # Clamp to valid range
        t_s = max(start_time_s, min(start_time_s + duration_s, start_time_s + t_s))
        t_ns: int = _to_ns(t_s)

        entries.append(
            TrafficEntry(
                relative_time_ns=t_ns,
                src_host=src_host,
                dst_host=dst_host,
                dst_ip=dst_ip,
                dst_port=dst_port,
                flow_id=flow_id,
                packet_size=packet_size,
                sequence_no=start_seq + i,
            )
        )

    return entries


def _incast_senders(num_senders: int) -> List[Tuple[str, str]]:
    """Return (host_name, ip) tuples for incast senders.

    h1 is the receiver at 10.0.0.1.
    Senders are h2..h(N+1) with IPs 10.0.0.2 .. 10.0.0.(N+1).
    """
    senders: List[Tuple[str, str]] = []
    for i in range(num_senders):
        sender_idx: int = i + 2  # h2, h3, ...
        host: str = f"h{sender_idx}"
        ip: str = f"10.0.0.{sender_idx}"
        senders.append((host, ip))
    return senders


def _distribute_round_robin(
    entries: List[TrafficEntry],
    senders: List[Tuple[str, str]],
    rng: random.Random,
) -> List[TrafficEntry]:
    """Reassign src_host and src IP round-robin across senders.

    Does NOT modify the original entries; returns a new list.
    This keeps the same timeline and just redistributes which host sends each
    packet.

    Args:
        entries: Packet entries with a single sender's metadata.
        senders: List of (host_name, ip) for available senders.
        rng: Random instance (reserved for future shuffling; currently unused).

    Returns:
        New list of TrafficEntry with src_host/src_ip reassigned round-robin.
    """
    if not entries or len(senders) <= 1:
        return entries

    num_senders: int = len(senders)
    result: List[TrafficEntry] = []
    for idx, entry in enumerate(entries):
        sender_host, sender_ip = senders[idx % num_senders]
        result.append(
            TrafficEntry(
                relative_time_ns=entry.relative_time_ns,
                src_host=sender_host,
                dst_host=entry.dst_host,
                dst_ip=entry.dst_ip,
                dst_port=entry.dst_port,
                flow_id=idx % num_senders,
                packet_size=entry.packet_size,
                sequence_no=idx // num_senders,
            )
        )

    # Sort by relative_time_ns to maintain timeline order
    result.sort(key=lambda e: e.relative_time_ns)
    return result


# ---------------------------------------------------------------------------
# Workload generators
# ---------------------------------------------------------------------------


def generate_stable(
    seed: int,
    topology: Any,
    config: dict,
    load_ratio: float,
    duration_s: float,
    runtime: Optional[dict] = None,
) -> List[TrafficEntry]:
    """Constant-rate workload on a single flow h1 -> h2.

    Packet rate = bottleneck_rate_pps * load_ratio.
    Uniform inter-packet spacing.
    """
    rate_pps: int = _resolve_bottleneck_rate(config, runtime)
    pps: float = rate_pps * load_ratio
    packet_size: int = _resolve_packet_size(config)

    return _uniform_packets(
        rate_pps=pps,
        start_time_s=0.0,
        duration_s=duration_s,
        src_host=DEFAULT_SRC_HOST,
        dst_host=DEFAULT_DST_HOST,
        dst_ip=DEFAULT_DST_IP,
        dst_port=DEFAULT_DST_PORT,
        flow_id=0,
        packet_size=packet_size,
    )


def generate_ramp(
    seed: int,
    topology: Any,
    config: dict,
    start_load: float,
    end_load: float,
    duration_s: float,
    runtime: Optional[dict] = None,
) -> List[TrafficEntry]:
    """Linearly increasing load from start_load to end_load over duration_s.

    Single flow h1 -> h2.
    Rate at time t: r0 + (r1 - r0) * t / duration_s
    """
    rate_pps: int = _resolve_bottleneck_rate(config, runtime)
    r0: float = rate_pps * start_load
    r1: float = rate_pps * end_load
    packet_size: int = _resolve_packet_size(config)

    return _ramp_packets(
        start_rate_pps=r0,
        end_rate_pps=r1,
        start_time_s=0.0,
        duration_s=duration_s,
        src_host=DEFAULT_SRC_HOST,
        dst_host=DEFAULT_DST_HOST,
        dst_ip=DEFAULT_DST_IP,
        dst_port=DEFAULT_DST_PORT,
        flow_id=0,
        packet_size=packet_size,
    )


def generate_step(
    seed: int,
    topology: Any,
    config: dict,
    load_before: float,
    load_after: float,
    switch_time_s: float,
    total_duration_s: float,
    runtime: Optional[dict] = None,
) -> List[TrafficEntry]:
    """Step-change workload: load_before for switch_time_s, then load_after.

    Single flow h1 -> h2.
    """
    rate_pps: int = _resolve_bottleneck_rate(config, runtime)
    packet_size: int = _resolve_packet_size(config)

    entries: List[TrafficEntry] = []

    # Segment 1: load_before
    before_pps: float = rate_pps * load_before
    first_dur: float = min(switch_time_s, total_duration_s)
    if first_dur > 0:
        entries.extend(
            _uniform_packets(
                rate_pps=before_pps,
                start_time_s=0.0,
                duration_s=first_dur,
                src_host=DEFAULT_SRC_HOST,
                dst_host=DEFAULT_DST_HOST,
                dst_ip=DEFAULT_DST_IP,
                dst_port=DEFAULT_DST_PORT,
                flow_id=0,
                packet_size=packet_size,
            )
        )

    # Segment 2: load_after
    remaining: float = max(0.0, total_duration_s - switch_time_s)
    if remaining > 0:
        after_pps: float = rate_pps * load_after
        seq_start: int = len(entries)
        entries.extend(
            _uniform_packets(
                rate_pps=after_pps,
                start_time_s=switch_time_s,
                duration_s=remaining,
                src_host=DEFAULT_SRC_HOST,
                dst_host=DEFAULT_DST_HOST,
                dst_ip=DEFAULT_DST_IP,
                dst_port=DEFAULT_DST_PORT,
                flow_id=0,
                packet_size=packet_size,
                start_seq=seq_start,
            )
        )

    entries.sort(key=lambda e: e.relative_time_ns)
    return entries


def generate_periodic_burst(
    seed: int,
    topology: Any,
    config: dict,
    burst_load: float,
    bg_load: float,
    burst_duration_ms: int,
    period_ms: int,
    total_duration_s: float,
    runtime: Optional[dict] = None,
) -> List[TrafficEntry]:
    """Periodic on/off burst workload.

    Alternates between burst_load and bg_load with period period_ms.
    Each burst lasts burst_duration_ms; the remainder of the period is bg_load.

    Single flow h1 -> h2.
    """
    rate_pps: int = _resolve_bottleneck_rate(config, runtime)
    packet_size: int = _resolve_packet_size(config)

    burst_dur_s: float = burst_duration_ms * _MS_TO_SECONDS
    period_s: float = period_ms * _MS_TO_SECONDS

    if period_s <= 0:
        # Degenerate: treat as pure bg_load
        return _uniform_packets(
            rate_pps=rate_pps * bg_load,
            start_time_s=0.0,
            duration_s=total_duration_s,
            src_host=DEFAULT_SRC_HOST,
            dst_host=DEFAULT_DST_HOST,
            dst_ip=DEFAULT_DST_IP,
            dst_port=DEFAULT_DST_PORT,
            flow_id=0,
            packet_size=packet_size,
        )

    burst_pps: float = rate_pps * burst_load
    bg_pps: float = rate_pps * bg_load

    entries: List[TrafficEntry] = []
    seq: int = 0

    t: float = 0.0
    while t < total_duration_s:
        # Burst phase
        burst_start: float = t
        burst_end: float = min(t + burst_dur_s, total_duration_s)
        actual_burst_dur: float = burst_end - burst_start
        if actual_burst_dur > 0 and burst_pps > 0:
            burst_entries: List[TrafficEntry] = _uniform_packets(
                rate_pps=burst_pps,
                start_time_s=burst_start,
                duration_s=actual_burst_dur,
                src_host=DEFAULT_SRC_HOST,
                dst_host=DEFAULT_DST_HOST,
                dst_ip=DEFAULT_DST_IP,
                dst_port=DEFAULT_DST_PORT,
                flow_id=0,
                packet_size=packet_size,
                start_seq=seq,
            )
            entries.extend(burst_entries)
            seq += len(burst_entries)

        # Background phase
        bg_start: float = burst_end
        bg_end: float = min(t + period_s, total_duration_s)
        actual_bg_dur: float = bg_end - bg_start
        if actual_bg_dur > 0 and bg_pps > 0:
            bg_entries: List[TrafficEntry] = _uniform_packets(
                rate_pps=bg_pps,
                start_time_s=bg_start,
                duration_s=actual_bg_dur,
                src_host=DEFAULT_SRC_HOST,
                dst_host=DEFAULT_DST_HOST,
                dst_ip=DEFAULT_DST_IP,
                dst_port=DEFAULT_DST_PORT,
                flow_id=0,
                packet_size=packet_size,
                start_seq=seq,
            )
            entries.extend(bg_entries)
            seq += len(bg_entries)

        t += period_s

    entries.sort(key=lambda e: e.relative_time_ns)
    return entries


def generate_mixed(
    seed: int,
    topology: Any,
    config: dict,
    total_duration_s: float,
    runtime: Optional[dict] = None,
) -> List[TrafficEntry]:
    """Mixed workload combining stable, ramp, and burst segments.

    Single flow h1 -> h2.

    The mix pattern is deterministic:
      - Segment 1 (0 -- T/3):       stable at 0.5C.
      - Segment 2 (T/3 -- 2T/3):    ramp 0.5C -> 1.5C.
      - Segment 3 (2T/3 -- T):      periodic burst (burst 2C, bg 0.3C,
                                    burst 100 ms, period 500 ms).
    """
    rate_pps: int = _resolve_bottleneck_rate(config, runtime)
    packet_size: int = _resolve_packet_size(config)

    seg_dur: float = total_duration_s / 3.0
    entries: List[TrafficEntry] = []

    # Segment 1: stable at 0.5C
    seg1_entries: List[TrafficEntry] = _uniform_packets(
        rate_pps=rate_pps * 0.5,
        start_time_s=0.0,
        duration_s=seg_dur,
        src_host=DEFAULT_SRC_HOST,
        dst_host=DEFAULT_DST_HOST,
        dst_ip=DEFAULT_DST_IP,
        dst_port=DEFAULT_DST_PORT,
        flow_id=0,
        packet_size=packet_size,
    )
    entries.extend(seg1_entries)
    seq: int = len(seg1_entries)

    # Segment 2: ramp 0.5C -> 1.5C
    seg2_entries: List[TrafficEntry] = _ramp_packets(
        start_rate_pps=rate_pps * 0.5,
        end_rate_pps=rate_pps * 1.5,
        start_time_s=seg_dur,
        duration_s=seg_dur,
        src_host=DEFAULT_SRC_HOST,
        dst_host=DEFAULT_DST_HOST,
        dst_ip=DEFAULT_DST_IP,
        dst_port=DEFAULT_DST_PORT,
        flow_id=0,
        packet_size=packet_size,
        start_seq=seq,
    )
    entries.extend(seg2_entries)
    seq += len(seg2_entries)

    # Segment 3: periodic burst 2C / 0.3C
    seg3_start: float = 2.0 * seg_dur
    seg3_dur: float = total_duration_s - seg3_start
    if seg3_dur > 0:
        seg3_entries: List[TrafficEntry] = generate_periodic_burst(
            seed=seed,
            topology=topology,
            config=config,
            burst_load=2.0,
            bg_load=0.3,
            burst_duration_ms=100,
            period_ms=500,
            total_duration_s=seg3_dur,
            runtime=runtime,
        )
        # Shift times for segment 3
        for e in seg3_entries:
            e.relative_time_ns = _to_ns(
                seg3_start + e.relative_time_ns / _SECONDS_TO_NANOS
            )
        # Re-number sequences
        for idx, e in enumerate(seg3_entries):
            e.sequence_no = seq + idx
        entries.extend(seg3_entries)

    entries.sort(key=lambda e: e.relative_time_ns)
    return entries


def generate_microburst(
    seed: int,
    topology: Any,
    config: dict,
    intensity_C: float,
    bg_load_C: float,
    burst_duration_ms: int,
    total_duration_s: float,
    runtime: Optional[dict] = None,
    num_senders: int = DEFAULT_NUM_SENDERS,
) -> List[TrafficEntry]:
    """Microburst workload for incast topology.

    A single microburst is placed at 40% of total_duration_s.  During the burst
    aggregate offered load is intensity_C * bottleneck_rate_pps (burst load
    *replaces* background, it does not add on top).  During non-burst intervals
    the load is bg_load_C * bottleneck_rate_pps.

    Burst packets are distributed uniformly across *num_senders* senders.

    Args:
        intensity_C: Aggregate offered load during burst as a multiple of C
                     (e.g. 2.0 means 2C).
        bg_load_C: Background load during non-burst periods as a multiple of C.
        burst_duration_ms: Duration of the single burst in milliseconds.
        total_duration_s: Total experiment duration in seconds.
        runtime: Optional runtime config dict.  ``bottleneck_rate_pps`` is read
                 from here or from *config*.
        num_senders: Number of incast senders (h2..hN).
    """
    rng: random.Random = _make_rng(seed)
    rate_pps: int = _resolve_bottleneck_rate(config, runtime)
    packet_size: int = _resolve_packet_size(config)

    senders: List[Tuple[str, str]] = _incast_senders(num_senders)

    burst_dur_s: float = burst_duration_ms * _MS_TO_SECONDS
    # Place burst at 40 % of total duration (deterministic)
    burst_start_s: float = total_duration_s * 0.4
    burst_end_s: float = burst_start_s + burst_dur_s

    bg_pps: float = rate_pps * bg_load_C
    burst_pps: float = rate_pps * intensity_C

    entries: List[TrafficEntry] = []
    seq: int = 0  # global sequence counter

    # --- Pre-burst background ---
    if burst_start_s > 0 and bg_pps > 0:
        pre_entries: List[TrafficEntry] = _uniform_packets(
            rate_pps=bg_pps,
            start_time_s=0.0,
            duration_s=burst_start_s,
            src_host=senders[0][0],       # placeholder; reassigned below
            dst_host=INCAST_RX_HOST,
            dst_ip=INCAST_RX_IP,
            dst_port=INCAST_DST_PORT,
            flow_id=0,
            packet_size=packet_size,
            start_seq=seq,
        )
        pre_entries = _distribute_round_robin(pre_entries, senders, rng)
        entries.extend(pre_entries)
        seq += len(pre_entries)

    # --- Burst ---
    if burst_dur_s > 0 and burst_pps > 0:
        # Total burst packets (aggregate)
        burst_n: int = math.ceil(burst_pps * burst_dur_s)
        # Each sender gets roughly burst_n / num_senders packets, uniformly spaced
        per_sender_n: int = math.ceil(burst_n / num_senders)

        for sender_idx, (sender_host, sender_ip) in enumerate(senders):
            for i in range(per_sender_n):
                t_s: float = burst_start_s + (i + 0.5) / per_sender_n * burst_dur_s
                t_ns: int = _to_ns(t_s)

                entries.append(
                    TrafficEntry(
                        relative_time_ns=t_ns,
                        src_host=sender_host,
                        dst_host=INCAST_RX_HOST,
                        dst_ip=INCAST_RX_IP,
                        dst_port=INCAST_DST_PORT,
                        flow_id=sender_idx,
                        packet_size=packet_size,
                        sequence_no=seq + i,
                    )
                )
            seq += per_sender_n

    # --- Post-burst background ---
    post_start_s: float = burst_end_s
    post_dur_s: float = max(0.0, total_duration_s - post_start_s)
    if post_dur_s > 0 and bg_pps > 0:
        post_entries: List[TrafficEntry] = _uniform_packets(
            rate_pps=bg_pps,
            start_time_s=post_start_s,
            duration_s=post_dur_s,
            src_host=senders[0][0],       # placeholder; reassigned below
            dst_host=INCAST_RX_HOST,
            dst_ip=INCAST_RX_IP,
            dst_port=INCAST_DST_PORT,
            flow_id=0,
            packet_size=packet_size,
            start_seq=seq,
        )
        post_entries = _distribute_round_robin(post_entries, senders, rng)
        entries.extend(post_entries)

    entries.sort(key=lambda e: e.relative_time_ns)
    return entries


def generate_incast_stable(
    seed: int,
    topology: Any,
    config: dict,
    load_ratio: float,
    duration_s: float,
    runtime: Optional[dict] = None,
    num_senders: int = DEFAULT_NUM_SENDERS,
) -> List[TrafficEntry]:
    """Incast constant-rate workload.

    Total packet rate is distributed round-robin across *num_senders* senders,
    all targeting h1 (10.0.0.1).
    """
    rng: random.Random = _make_rng(seed)
    rate_pps: int = _resolve_bottleneck_rate(config, runtime)
    packet_size: int = _resolve_packet_size(config)
    senders: List[Tuple[str, str]] = _incast_senders(num_senders)

    pps: float = rate_pps * load_ratio

    # Generate single-flow timeline first, then distribute
    single_entries: List[TrafficEntry] = _uniform_packets(
        rate_pps=pps,
        start_time_s=0.0,
        duration_s=duration_s,
        src_host=senders[0][0],       # placeholder
        dst_host=INCAST_RX_HOST,
        dst_ip=INCAST_RX_IP,
        dst_port=INCAST_DST_PORT,
        flow_id=0,
        packet_size=packet_size,
    )

    return _distribute_round_robin(single_entries, senders, rng)


def generate_incast_ramp(
    seed: int,
    topology: Any,
    config: dict,
    start_load: float,
    end_load: float,
    duration_s: float,
    runtime: Optional[dict] = None,
    num_senders: int = DEFAULT_NUM_SENDERS,
) -> List[TrafficEntry]:
    """Incast ramping workload.

    Total packet rate ramps from start_load to end_load and is distributed
    round-robin across *num_senders* senders, all targeting h1 (10.0.0.1).
    """
    rng: random.Random = _make_rng(seed)
    rate_pps: int = _resolve_bottleneck_rate(config, runtime)
    packet_size: int = _resolve_packet_size(config)
    senders: List[Tuple[str, str]] = _incast_senders(num_senders)

    r0: float = rate_pps * start_load
    r1: float = rate_pps * end_load

    single_entries: List[TrafficEntry] = _ramp_packets(
        start_rate_pps=r0,
        end_rate_pps=r1,
        start_time_s=0.0,
        duration_s=duration_s,
        src_host=senders[0][0],       # placeholder
        dst_host=INCAST_RX_HOST,
        dst_ip=INCAST_RX_IP,
        dst_port=INCAST_DST_PORT,
        flow_id=0,
        packet_size=packet_size,
    )

    return _distribute_round_robin(single_entries, senders, rng)


# ---------------------------------------------------------------------------
# Workload registry
# ---------------------------------------------------------------------------

WorkloadFunc = Callable[..., List[TrafficEntry]]

WORKLOAD_REGISTRY: Dict[str, Tuple[WorkloadFunc, dict]] = {
    "stable": (
        generate_stable,
        {"load_ratio": 1.5, "duration_s": 30},
    ),
    "ramp": (
        generate_ramp,
        {"start_load": 0.1, "end_load": 2.0, "duration_s": 30},
    ),
    "step": (
        generate_step,
        {
            "load_before": 0.3,
            "load_after": 1.5,
            "switch_time_s": 10.0,
            "total_duration_s": 30,
        },
    ),
    "periodic_burst": (
        generate_periodic_burst,
        {
            "burst_load": 2.0,
            "bg_load": 0.3,
            "burst_duration_ms": 100,
            "period_ms": 500,
            "total_duration_s": 30,
        },
    ),
    "mixed": (
        generate_mixed,
        {"total_duration_s": 30},
    ),
    "microburst": (
        generate_microburst,
        {
            "intensity_C": 2.0,
            "bg_load_C": 0.7,
            "burst_duration_ms": 20,
            "total_duration_s": 30,
            "num_senders": 4,
        },
    ),
    "incast_stable": (
        generate_incast_stable,
        {"load_ratio": 1.5, "duration_s": 30, "num_senders": 4},
    ),
    "incast_ramp": (
        generate_incast_ramp,
        {"start_load": 0.1, "end_load": 2.0, "duration_s": 30, "num_senders": 4},
    ),
}


# ---------------------------------------------------------------------------
# Convenience: compose a TrafficEntry list from a workload name
# ---------------------------------------------------------------------------


def generate_from_name(
    name: str,
    seed: int,
    topology: Any,
    config: dict,
    runtime: Optional[dict] = None,
    **override_kwargs: Any,
) -> List[TrafficEntry]:
    """Look up a workload by name and generate TrafficEntry list.

    Default kwargs from WORKLOAD_REGISTRY are used, and any *override_kwargs*
    take precedence.  ``runtime`` is forwarded to the generator.
    """
    if name not in WORKLOAD_REGISTRY:
        raise ValueError(
            f"Unknown workload '{name}'. Known: {sorted(WORKLOAD_REGISTRY.keys())}"
        )

    func, defaults = WORKLOAD_REGISTRY[name]
    kwargs: dict = {**defaults, **override_kwargs}
    return func(seed=seed, topology=topology, config=config, runtime=runtime, **kwargs)


# ---------------------------------------------------------------------------
# Main entry point (called by experiments.traffic_generator)
# ---------------------------------------------------------------------------


def generate_workload(
    name: str,
    seed: int,
    topology: dict,
    config: dict,
) -> list:
    """Generate a traffic plan for the named workload.

    This is the primary entry point called by
    :func:`experiments.traffic_generator.generate_traffic_plan`.

    Supports compound workload names like:
      - ``stable_60`` → stable load at 60% of C
      - ``ramp_medium`` → ramp from 20% to 120% of C
      - ``microburst_2C_10ms`` → microburst at 2C for 10ms

    Args:
        name: Workload name.
        seed: PRNG seed for deterministic plans.
        topology: Topology dict from SwitchManager.
        config: Resolved experiment configuration dict.

    Returns:
        List of TrafficEntry objects sorted by relative_time_ns.
    """
    # Handle legacy workload names used by the experiment runner
    legacy_map = {
        "stable_60": ("stable", {"load_ratio": 0.60, "duration_s": 30}),
        "stable_80": ("stable", {"load_ratio": 0.80, "duration_s": 30}),
        "ramp_slow": ("ramp", {"start_load": 0.50, "end_load": 1.20, "duration_s": 30}),
        "ramp_medium": ("ramp", {"start_load": 0.50, "end_load": 1.50, "duration_s": 30}),
        "ramp_fast": ("ramp", {"start_load": 0.50, "end_load": 2.00, "duration_s": 30}),
        "step": ("step", {}),
        "periodic_burst": ("periodic_burst", {}),
        "mixed": ("mixed", {}),
    }

    if name in legacy_map:
        base_name, overrides = legacy_map[name]
        return generate_from_name(base_name, seed, topology, config, **overrides)

    # Handle microburst names: microburst_<intensity>C_<dur>ms
    if name.startswith("microburst_"):
        parts = name.replace("microburst_", "").split("_")
        if len(parts) == 2:
            intensity_str = parts[0].replace("C", "")
            dur_str = parts[1].replace("ms", "")
            try:
                intensity = float(intensity_str)
                burst_duration_ms = float(dur_str)
            except ValueError:
                raise ValueError(f"Cannot parse microburst workload name: {name}")
            return generate_from_name(
                "microburst", seed, topology, config,
                intensity_C=intensity,
                burst_duration_ms=burst_duration_ms,
            )

    # Fall back to direct registry lookup
    return generate_from_name(name, seed, topology, config)
