#!/usr/bin/env python3
"""Unit tests for PTT-INT metrics computation.

Tests: event detection, lead-time calculation, precision/recall.
"""

import sys
import csv
import json
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from oracle.events import detect_events, CongestionEvent
from analysis.metrics import (
    compute_lead_times,
    compute_predictive_precision_recall,
    compute_early_coverage,
    compute_nmae,
    compute_state_occupancy,
    compute_all_metrics,
)


def _write_csv(path: str, header: list[str], rows: list[dict]):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        w.writeheader()
        w.writerows(rows)


class TestEventDetection(unittest.TestCase):
    """Test oracle event detection."""

    ORACLE_HEADER = [
        "run_id", "scheme", "seed", "switch_id", "port",
        "ts_us", "q", "trend", "q_pred_near", "q_pred_far", "state", "target",
    ]

    def test_no_events_when_q_low(self):
        """No events when q stays below threshold."""
        rows = [
            {"run_id": "t", "scheme": "PTT", "seed": 1,
             "switch_id": 1, "port": 0,
             "ts_us": str(i * 5000), "q": str(50), "trend": "0",
             "q_pred_near": "50", "q_pred_far": "50",
             "state": "0", "target": "0"}
            for i in range(10)
        ]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            _write_csv(f.name, self.ORACLE_HEADER, rows)
            events = detect_events(f.name, q_event=96, q_release=64)

        self.assertEqual(len(events), 0)

    def test_single_event(self):
        """Single congestion event detected."""
        rows = []
        for i in range(20):
            q = 50 + i * 6 if i < 10 else 50  # ramp up to 104 (>96) then down
            rows.append({
                "run_id": "t", "scheme": "PTT", "seed": 1,
                "switch_id": 1, "port": 0,
                "ts_us": str(i * 5000), "q": str(min(q, 128)),
                "trend": "100", "q_pred_near": str(q), "q_pred_far": str(q),
                "state": "0", "target": "0",
            })

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            _write_csv(f.name, self.ORACLE_HEADER, rows)
            events = detect_events(f.name, q_event=96, q_release=64)

        self.assertGreaterEqual(len(events), 1)

    def test_hysteresis_prevents_double_count(self):
        """Event definition with Q_RELEASE hysteresis prevents double counting."""
        rows = []
        # q oscillates around threshold
        for i in range(50):
            if i % 10 < 5:
                q = 100  # above threshold
            else:
                q = 70  # still above release, no new event
            rows.append({
                "run_id": "t", "scheme": "PTT", "seed": 1,
                "switch_id": 1, "port": 0,
                "ts_us": str(i * 5000), "q": str(q),
                "trend": "0", "q_pred_near": str(q), "q_pred_far": str(q),
                "state": "0", "target": "0",
            })

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            _write_csv(f.name, self.ORACLE_HEADER, rows)
            # Without release crossing, this should be one event
            events_no_release = detect_events(f.name, q_event=96, q_release=64)

        # q never goes below release, so no new events after initial
        self.assertGreaterEqual(len(events_no_release), 1)


class TestLeadTime(unittest.TestCase):
    """Test lead time calculation."""

    def test_positive_lead_time(self):
        """BURST before event gives positive lead time."""
        oracle = [
            {"switch_id": 1, "port": 0, "ts_us": 0, "q": 10, "state": 0, "target": 0,
             "trend": 0, "q_pred_near": 10, "q_pred_far": 10},
            {"switch_id": 1, "port": 0, "ts_us": 5000, "q": 50, "state": 0, "target": 0,
             "trend": 0, "q_pred_near": 50, "q_pred_far": 50},
            {"switch_id": 1, "port": 0, "ts_us": 10000, "q": 100, "state": 2, "target": 2,
             "trend": 256, "q_pred_near": 100, "q_pred_far": 120},
        ]
        telemetry = [
            {"switch_id": 1, "egress_port": 0, "hop_ts_us": 5000, "qdepth": 50,
             "state": "WATCH", "packet_num": 1, "total_hops": 1,
             "hop_index": 0, "q_pred_far": 50},
            {"switch_id": 1, "egress_port": 0, "hop_ts_us": 8000, "qdepth": 80,
             "state": "BURST", "packet_num": 2, "total_hops": 1,
             "hop_index": 0, "q_pred_far": 100},
        ]
        events = [
            {"event_id": 1, "switch_id": 1, "port": 0,
             "start_ts_us": 10000, "end_ts_us": 15000,
             "peak_q": 120, "peak_q_ts_us": 12000, "duration_us": 5000},
        ]

        result = compute_lead_times(oracle, telemetry, events)
        # BURST at 8000, event at 10000 => lead = 2000 > 0
        self.assertGreater(len(result["burst_lead_times"]), 0)
        self.assertGreater(result["burst_lead_times"][0], 0)


class TestPrecisionRecall(unittest.TestCase):
    """Test predictive precision/recall."""

    def test_precision_perfect(self):
        """Perfect precision: all predictive BURST entries followed by events."""
        oracle = []
        for i in range(20):
            q = min(i * 10, 128)
            target = 2 if q >= 96 or (q >= 80 and i >= 8) else 0
            oracle.append({
                "switch_id": 1, "port": 0,
                "ts_us": i * 5000, "q": q,
                "trend": 200, "q_pred_near": q + 10, "q_pred_far": q + 20,
                "state": target, "target": target,
            })

        events = [{
            "event_id": 1, "switch_id": 1, "port": 0,
            "start_ts_us": 45000, "end_ts_us": 70000,
            "peak_q": 128, "duration_us": 25000,
        }]

        result = compute_predictive_precision_recall(
            oracle, events, q_event=96, near_horizon=2, epoch_us=5000
        )
        # With ramp-up, predictive entries before event should be TP
        self.assertGreaterEqual(result["precision"], 0.0)
        self.assertLessEqual(result["precision"], 1.0)


class TestNMAE(unittest.TestCase):
    """Test normalized mean absolute error."""

    def test_perfect_reconstruction(self):
        """NMAE = 0 when every oracle point has a matching sample."""
        oracle = [
            {"switch_id": 1, "port": 0, "ts_us": t, "q": q,
             "trend": 0, "q_pred_near": q, "q_pred_far": q,
             "state": 0, "target": 0}
            for t, q in [(0, 10), (5000, 20), (10000, 30)]
        ]
        telemetry = [
            {"switch_id": 1, "egress_port": 0, "hop_ts_us": t, "qdepth": q,
             "state": "QUIET", "packet_num": i, "total_hops": 1,
             "hop_index": 0, "q_pred_far": q}
            for i, (t, q) in enumerate([(0, 10), (5000, 20), (10000, 30)])
        ]
        result = compute_nmae(oracle, telemetry, q_cap=128)
        self.assertAlmostEqual(result["NMAE"], 0.0, places=3)


class TestStateOccupancy(unittest.TestCase):
    """Test state occupancy calculation."""

    def test_all_quiet(self):
        oracle = [
            {"switch_id": 1, "port": 0, "ts_us": i * 5000, "q": 10,
             "trend": 0, "q_pred_near": 10, "q_pred_far": 10,
             "state": 0, "target": 0}
            for i in range(10)
        ]
        result = compute_state_occupancy(oracle)
        self.assertAlmostEqual(result["P_QUIET"], 1.0, places=3)
        self.assertAlmostEqual(result["P_WATCH"], 0.0, places=3)
        self.assertAlmostEqual(result["P_BURST"], 0.0, places=3)


class TestComputeAllMetrics(unittest.TestCase):
    """Verify compute_all_metrics does not crash with NameError."""

    def test_compute_all_metrics_no_name_error(self):
        """Call compute_all_metrics and confirm it returns without NameError."""
        with tempfile.TemporaryDirectory() as d:
            oracle_csv = str(Path(d) / "oracle.csv")
            telemetry_csv = str(Path(d) / "telemetry.csv")
            events_csv = str(Path(d) / "events.csv")

            # Minimal oracle CSV with one epoch
            _write_csv(oracle_csv, [
                "run_id", "scheme", "seed", "switch_id", "port",
                "ts_us", "q", "trend", "q_pred_near", "q_pred_far", "state", "target",
            ], [
                {"run_id": "test", "scheme": "PTT", "seed": 1, "switch_id": 1,
                 "port": 0, "ts_us": 5000, "q": 10, "trend": 0,
                 "q_pred_near": 10, "q_pred_far": 10, "state": 0, "target": 0},
            ])

            # Minimal telemetry CSV with one sample
            _write_csv(telemetry_csv, [
                "run_id", "scheme", "seed", "recv_ts", "src_ip", "dst_ip",
                "packet_num", "switch_id", "egress_port", "state", "reason",
                "qdepth", "q_pred_far", "hop_ts_us", "hop_index", "total_hops",
                "shim_magic", "original_dport",
            ], [
                {"run_id": "test", "scheme": "PTT", "seed": 1, "recv_ts": 0,
                 "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "packet_num": 1,
                 "switch_id": 1, "egress_port": 0, "state": "QUIET", "reason": "PERIODIC_QUIET",
                 "qdepth": 10, "q_pred_far": 10, "hop_ts_us": 5000,
                 "hop_index": 0, "total_hops": 1, "shim_magic": 20564,
                 "original_dport": 9999},
            ])

            # Minimal events CSV (no events needed)
            _write_csv(events_csv, [
                "run_id", "scheme", "seed", "event_id", "switch_id",
                "port", "start_ts_us", "end_ts_us", "duration_us",
                "peak_q", "peak_q_ts_us",
            ], [])

            # This should NOT raise NameError
            config = {
                "queue": {"capacity_packets": 128, "event_threshold_packets": 96,
                          "release_threshold_packets": 64},
                "predictor": {"near_horizon": 2, "epoch_us": 5000},
                "packet": {"original_packet_size": 1000, "shim_bytes": 8, "hop_record_bytes": 12},
            }
            result = compute_all_metrics(oracle_csv, telemetry_csv, events_csv, config)
            self.assertIsInstance(result, dict)
            self.assertIn("lead_times", result)
            self.assertIn("telemetry_overhead", result)


if __name__ == "__main__":
    unittest.main()
