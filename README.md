# PTT-INT reference implementation

This repository implements PTT-INT, described in *Ahead of Congestion: Predictive Time-to-Threshold Triggering for In-Band Network Telemetry*. It contains the P4 data plane, switch configuration, a telemetry collector, and functional verification.

The reference is a P4_16/v1model program for BMv2 `simple_switch`. Each egress port maintains a Q8 one-sided EWMA of positive dequeue-queue increments. Near/far projections drive QUIET, WATCH, and BURST sampling. The predictor runs at packet-driven epochs; the committed state controls every eligible packet between epochs.

## Build and verify

Install Python dependencies in your environment:

```sh
python3 -m pip install -r requirements.txt
make build
make test
```

Building requires `p4c-bm2-ss` on `PATH`. Validation used p4c-bm2-ss 1.2.5.10, BMv2 simple_switch 1.15.0, and Python 3.12.3 on Ubuntu 24.04.

`make build` validates [config/default.yaml](config/default.yaml), generates `build/generated_params.p4`, and compiles the sole production entry point, [p4src/ptt_int.p4](p4src/ptt_int.p4), into `build/ptt_int.json`. Generated files are ignored by Git. Compiler and configuration errors fail the build.

Full verification also requires `simple_switch`, `simple_switch_CLI`, `nnpy`, and BMv2's generated Python modules (`bm_runtime`, `sswitch_runtime`, and their Thrift dependency) in the test interpreter's import path:

```sh
python3 -m pip install -r requirements-test.txt
make check
```

If BMv2 installed its Python modules in a separate environment, expose that environment's `site-packages` directory with `PYTHONPATH` when running `make check`, for example:

```sh
PYTHONPATH=/path/to/bmv2/site-packages make check
```

`make check` runs unit tests and actual BMv2 packet tests. Missing tools, missing dependencies, dropped expected packets, or mismatched observations fail the tests. The BMv2 tests use private packet-in sockets, temporary directories, and dynamically chosen Thrift ports; they need no root privileges or host interface changes. Packets still traverse BMv2's real forwarding and egress queues. Processes and sockets are removed on completion.

A separate [test adapter](tests/p4/deterministic.p4) supplies precise queue and 48-bit timestamp inputs to the same production telemetry control. Tests compare every output packet and all eight per-port registers with an integer model. The production entry point always reads real v1model metadata.

## Configure a switch

For existing interfaces `sw-in` and `sw-out`, for example:

```sh
sudo simple_switch -i 0@sw-in -i 1@sw-out --thrift-port 9090 build/ptt_int.json
```

In another terminal:

```sh
python3 control/configure_switch.py --thrift-port 9090 --switch-id 1 \
  --routes '[{"dst_ip":"10.0.0.2/32","port":1},{"dst_ip":"10.0.0.1/32","port":0}]'
python3 control/configure_queues.py --thrift-port 9090 --queue-depth 128 \
  --queue-rate 0 --ports 0,1
```

Queue capacity is in packets. Rate is packets/second; zero removes rate limiting. Set the runtime capacity to match the configured `capacity_packets`. An omitted `--ports` configures all queues. Switch IDs are 12 bits; usable forwarding ports are 0–510 (511 is BMv2's default drop port).

Forwarding uses an IPv4 longest-prefix table and preserves Ethernet addresses. Configure link-layer addressing/static neighbors for the path. Unrouted packets, expired TTLs, bad IPv4 checksums, malformed headers, and non-IPv4 frames are dropped. Valid TCP, ICMP, and IPv4 fragments are forwarded without telemetry. IPv4 options are preserved and included in checksum handling.

Inspect state with the installed BMv2 CLI:

```text
register_read state_reg 1
register_read trend_q8_reg 1
register_read sample_counter_reg 1
register_read last_report_reg 1
```

## Collect telemetry

```sh
python3 collector/parse_pcap.py --pcap capture.pcap --output telemetry.csv
```

Use `--int-port` and `--max-hops` if their configuration differs from the defaults. Each CSV row represents one declared hop record. Invalid/truncated PTT packets are excluded. Payload and Ethernet padding are never interpreted as additional records.

The prototype encapsulation is:

```text
Ethernet | IPv4 | UDP(dst=32768) | PTT shim (8 B) | hop records (12 B each) | payload
```

The first insertion saves the original UDP destination port and adds 20 bytes. Later selected hops prepend one 12-byte record; unselected hops preserve existing telemetry. Wire/CSV hop index 0 is the most recent insertion. At eight records, a selected hop sets overflow without inserting or advancing its report timestamp. Maximum addition is 104 bytes. IPv4 length and checksum are updated; modified UDP packets use the IPv4-permitted zero UDP checksum.

The hop fields are switch ID (12 bits), egress port (9), state (2), reason (3), queue depth (19), far projection (19), and timestamp low bits (32). State encodings are QUIET=0, WATCH=1, BURST=2. Reasons are QUIET sampling=0, WATCH sampling=1, BURST below current threshold=2, BURST at/above threshold=3, and freshness-forced reporting=4. State and reason are distinct: a retained BURST can report reason 2 without a new predictive transition.

Timestamps are switch-local microseconds; the wire field wraps after approximately 71.6 minutes. The collector exposes it as `hop_ts_low_us` and does not claim synchronized time across switches. The encapsulation is the paper's prototype format, not standardized INT-MD. It terminates at a collector; this implementation does not strip PTT or restore UDP ports for ordinary applications. Reserve sufficient path MTU for the added bytes.

## Parameters

| Parameter                        | Default                                |
| -------------------------------- | -------------------------------------- |
| Queue capacity / event / release | 128 / 96 / 64 packets                  |
| Minimum epoch spacing            | 5,000 µs                               |
| EWMA coefficient / scale         | 1/4 / Q8                               |
| Near / far horizons              | 2 / 8 epochs                           |
| Long-gap / idle reset            | >20,000 µs / ≥100,000 µs with q<64     |
| Downward recovery                | 3 normal lower-target epochs per level |
| QUIET / WATCH / BURST sampling   | 1/32 / 1/4 / 1                         |
| Maximum silence                  | 100,000 µs                             |
| Maximum hop records              | 8                                      |

Sampling tests the counter before incrementing, so a new port's first packet is selected. The instantaneous queue threshold changes the FSM only at a normal observation epoch. Initialization starts in QUIET; a long gap clears growth while retaining state and recovery evidence. Idle reset clears growth, state, and recovery only when the queue is below the release threshold. Freshness does not change the FSM and advances its timestamp only on successful insertion.

To build a different configuration without replacing the default artifact:

```sh
bash scripts/build.sh /path/to/config.yaml /path/to/output-directory
```

Supported horizons are ordered powers of two from 1 through 256; EWMA alpha is `1/(2^ewma_alpha_shift)`, with shift 1–8. Both EWMA terms and horizon shifts are generated from configuration. Sampling masks are `2^n-1`, with WATCH smaller than QUIET. The bounded parser supports 1–8 records. Idle reset and freshness are explicit durations, independent of epoch changes.

The tests establish BMv2 functional behavior; hardware resource mapping and line-rate feasibility remain outside this prototype's implementation scope.
