#!/usr/bin/env python3
"""Validate configuration and generate the constants consumed by p4c."""
import argparse
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = {
    "queue": {"capacity_packets", "event_threshold_packets", "release_threshold_packets"},
    "predictor": {"epoch_us", "ewma_alpha_shift", "near_horizon", "far_horizon"},
    "fsm": {"recovery_epochs", "gap_reset_multiple", "idle_reset_us"},
    "sampling": {"quiet_mask", "watch_mask"},
    "freshness": {"max_silence_us"},
    "packet": {"int_port", "max_hops"},
}


def parameters(cfg):
    if not isinstance(cfg, dict) or set(cfg) != set(SCHEMA):
        raise ValueError("configuration sections must match the default schema")
    for section, keys in SCHEMA.items():
        values = cfg[section]
        if not isinstance(values, dict) or set(values) != keys:
            raise ValueError(f"{section}: expected keys {sorted(keys)}")
        if any(type(value) is not int for value in values.values()):
            raise ValueError(f"{section}: parameters must be integers")
    q, p, f, s, t, pkt = (cfg[k] for k in SCHEMA)
    if not 0 <= q["release_threshold_packets"] < q["event_threshold_packets"] <= q["capacity_packets"] <= 0x7FFFF:
        raise ValueError("require 0 <= release < event <= capacity <= 524287")
    if not 1 <= p["ewma_alpha_shift"] <= 8:
        raise ValueError("Q8 EWMA requires alpha shift in [1, 8]")
    near, far = p["near_horizon"], p["far_horizon"]
    if not 1 <= near < far <= 256 or any(h & (h - 1) for h in (near, far)):
        raise ValueError("horizons must be ordered powers of two in [1, 256]")
    epoch = p["epoch_us"]
    gap = epoch * f["gap_reset_multiple"]
    if not 0 < epoch < gap < f["idle_reset_us"] < (1 << 47):
        raise ValueError("require 0 < epoch < gap < idle < 2^47 microseconds")
    if not 1 <= f["recovery_epochs"] <= 255:
        raise ValueError("recovery count must fit in 8 bits and be positive")
    if not 0 < t["max_silence_us"] < (1 << 47):
        raise ValueError("maximum silence must be in (0, 2^47) microseconds")
    if not 0 <= s["watch_mask"] < s["quiet_mask"] <= 0xFFFFFFFF or any(v & (v + 1) for v in s.values()):
        raise ValueError("sampling masks must be 2^n-1, with WATCH < QUIET")
    if not 1 <= pkt["int_port"] <= 65535 or not 1 <= pkt["max_hops"] <= 8:
        raise ValueError("INT port must be in [1, 65535], max_hops in [1, 8]")
    return {
        "Q_CAP": q["capacity_packets"], "Q_EVENT": q["event_threshold_packets"],
        "Q_RELEASE": q["release_threshold_packets"], "EPOCH_US": epoch,
        "EWMA_ALPHA_SHIFT": p["ewma_alpha_shift"],
        "EWMA_DELTA_SHIFT": 8 - p["ewma_alpha_shift"],
        "NEAR_SHIFT": 8 - (near.bit_length() - 1),
        "FAR_SHIFT": 8 - (far.bit_length() - 1),
        "RECOVERY_EPOCHS": f["recovery_epochs"], "GAP_RESET_US": gap,
        "IDLE_RESET_US": f["idle_reset_us"],
        "QUIET_MASK": s["quiet_mask"], "WATCH_MASK": s["watch_mask"],
        "MAX_SILENCE_US": t["max_silence_us"],
        "INT_PORT": pkt["int_port"], "MAX_HOPS": pkt["max_hops"],
    }


def generate(config_path, output_path):
    params = parameters(yaml.safe_load(Path(config_path).read_text()))
    content = "// Generated from validated YAML; do not edit.\n"
    content += "#ifndef PTT_GENERATED_PARAMS\n#define PTT_GENERATED_PARAMS\n"
    content += "".join(f"#define {key} {value}\n" for key, value in params.items())
    content += "#endif\n"
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content)
    return params


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "config/default.yaml")
    parser.add_argument("--output", type=Path, default=ROOT / "build/generated_params.p4")
    args = parser.parse_args()
    try:
        generate(args.config, args.output)
    except (ValueError, OSError, yaml.YAMLError) as exc:
        parser.exit(1, f"Invalid configuration: {exc}\n")


if __name__ == "__main__":
    main()
