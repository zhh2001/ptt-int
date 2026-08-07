# PTT-INT: Predictive Time-to-Threshold Triggered In-band Network Telemetry

## Overview

PTT-INT estimates short-horizon queue threshold crossing directly in the
programmable data plane and adapts telemetry resolution according to the
predicted time-to-threshold. The system uses a lightweight per-egress-port
predictor with Q8 fixed-point one-sided EWMA, dual near/far horizon
prediction, and a QUIET/WATCH/BURST three-state FSM with hysteresis.

## Environment

- P4_16 + v1model
- p4c-bm2-ss 1.2.5.10
- BMv2 simple_switch 1.15.0
- Mininet 2.3.0
- Python 3.12.3
- Ubuntu 24.04.4 LTS (WSL2)

## Quick Start

```bash
# Build P4 program
make build

# Run unit tests
make test

# Run smoke test (requires root for Mininet)
sudo make smoke

# Run full experiment matrix (requires root)
sudo bash scripts/reproduce_all.sh
```

## Repository Structure

```txt
ptt-int/
├── config/          # YAML configuration (single source of truth)
├── p4src/           # P4_16 program (monolithic + modular includes)
├── control/         # Switch/queue configuration via simple_switch_CLI
├── topology/        # Mininet topology scripts
├── traffic/         # Traffic generation (iperf3)
├── collector/       # Pcap parsing and PTT header dissection
├── oracle/          # BMv2 log parsing and event detection
├── experiments/     # Experiment runner and matrix executor
├── analysis/        # Metrics, reconstruction, aggregation, plots
├── tests/           # Unit tests and smoke test
├── results/         # Raw data, processed data, figures, tables
└── scripts/         # Build, smoke test, and reproduction scripts
```

## Telemetry Schemes

| Scheme | Mode | Description |
| -------- | ------ | ------------- |
| FULL | 0 | Every packet instrumented |
| PERIODIC_4 | 1 | 1/4 periodic sampling |
| PERIODIC_16 | 2 | 1/16 periodic sampling |
| PERIODIC_32 | 3 | 1/32 periodic sampling |
| REACTIVE | 4 | Full when q >= Q_EVENT, 1/32 background |
| DELTA | 5 | Trigger on `\|q - q_last\| >= Delta_Q` |
| PTT | 6 | Predictive QUIET/WATCH/BURST FSM |

## Key Parameters

| Parameter | Symbol | Default |
| ----------- | -------- | --------- |
| Queue capacity | Q_cap | 128 packets |
| Event threshold | Q_EVENT | 96 packets (0.75 × Q_cap) |
| Release threshold | Q_RELEASE | 64 packets (0.5 × Q_cap) |
| Epoch | W | 5000 µs |
| EWMA alpha | α | 1/4 |
| Near horizon | H_N | 2 epochs |
| Far horizon | H_F | 8 epochs |
| Recovery epochs | M | 3 |
| MAX_HOPS | — | 8 |
