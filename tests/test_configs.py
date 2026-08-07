#!/usr/bin/env python3
"""Unit tests for configuration validation."""

import sys
import yaml
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestConfigValidation(unittest.TestCase):
    """Test that default configuration is valid."""

    @classmethod
    def setUpClass(cls):
        config_path = Path(__file__).parent.parent / "config" / "default.yaml"
        with open(config_path) as f:
            cls.config = yaml.safe_load(f)

    def test_queue_config(self):
        q = self.config["queue"]
        self.assertIn("capacity_packets", q)
        self.assertIn("event_threshold_packets", q)
        self.assertIn("release_threshold_packets", q)
        self.assertGreater(q["capacity_packets"], 0)
        self.assertGreater(q["event_threshold_packets"], 0)
        self.assertLessEqual(q["event_threshold_packets"], q["capacity_packets"])
        self.assertLess(q["release_threshold_packets"], q["event_threshold_packets"])

    def test_predictor_config(self):
        p = self.config["predictor"]
        self.assertIn("epoch_us", p)
        self.assertIn("ewma_alpha_shift", p)
        self.assertIn("near_horizon", p)
        self.assertIn("far_horizon", p)
        self.assertGreater(p["epoch_us"], 0)
        self.assertGreater(p["near_horizon"], 0)
        self.assertGreater(p["far_horizon"], p["near_horizon"])
        self.assertGreater(p["ewma_alpha_shift"], 0)

    def test_fsm_config(self):
        fsm = self.config["fsm"]
        self.assertIn("recovery_epochs", fsm)
        self.assertIn("gap_reset_multiple", fsm)
        self.assertIn("idle_reset_multiple", fsm)
        self.assertGreater(fsm["recovery_epochs"], 0)
        self.assertGreater(fsm["gap_reset_multiple"], 0)
        self.assertGreater(fsm["idle_reset_multiple"], fsm["gap_reset_multiple"])

    def test_sampling_config(self):
        s = self.config["sampling"]
        self.assertIn("quiet_mask", s)
        self.assertIn("watch_mask", s)
        self.assertIn("burst_all", s)
        self.assertTrue(s["burst_all"])

    def test_packet_config(self):
        pkt = self.config["packet"]
        self.assertIn("int_port", pkt)
        self.assertIn("max_hops", pkt)
        self.assertIn("magic", pkt)
        self.assertGreater(pkt["max_hops"], 0)
        self.assertEqual(pkt["magic"], 0x5054)

    def test_scheme_modes(self):
        schemes = self.config["schemes"]
        self.assertEqual(schemes["FULL"], 0)
        self.assertEqual(schemes["PTT"], 6)

    def test_topology(self):
        topo = self.config["topology"]
        self.assertIn("switch_ids", topo)
        self.assertIn("s1", topo["switch_ids"])
        self.assertIn("s2", topo["switch_ids"])

    def test_freshness(self):
        fresh = self.config["freshness"]
        self.assertIn("max_silence_us", fresh)
        self.assertGreater(fresh["max_silence_us"], 0)

    def test_delta(self):
        delta = self.config["delta"]
        self.assertIn("threshold_packets", delta)
        self.assertGreater(delta["threshold_packets"], 0)

    def test_experiment_config(self):
        exp = self.config["experiment"]
        self.assertGreater(exp["default_duration_s"], 0)
        self.assertGreater(len(exp["default_seeds"]), 0)


class TestConfigConsistency(unittest.TestCase):
    """Test that derived parameters are consistent."""

    @classmethod
    def setUpClass(cls):
        config_path = Path(__file__).parent.parent / "config" / "default.yaml"
        with open(config_path) as f:
            cls.config = yaml.safe_load(f)

    def test_event_threshold_release_ratio(self):
        """Q_EVENT and Q_RELEASE have correct relationship."""
        q = self.config["queue"]
        ratio_event = q["event_threshold_packets"] / q["capacity_packets"]
        ratio_release = q["release_threshold_packets"] / q["capacity_packets"]
        # Q_EVENT = 0.75 * Q_cap, Q_RELEASE = 0.5 * Q_cap
        self.assertAlmostEqual(ratio_event, 0.75, delta=0.05)
        self.assertAlmostEqual(ratio_release, 0.50, delta=0.05)

    def test_near_horizon_less_than_far(self):
        p = self.config["predictor"]
        self.assertLess(p["near_horizon"], p["far_horizon"])

    def test_epoch_shift_consistency(self):
        """EWMA alpha = 1/4 gives shift of 2."""
        p = self.config["predictor"]
        self.assertEqual(1 << p["ewma_alpha_shift"], 4)  # 1/alpha = 4

    def test_idle_gap_gt_gap_reset(self):
        """T_idle > T_gap."""
        fsm = self.config["fsm"]
        self.assertGreater(fsm["idle_reset_multiple"], fsm["gap_reset_multiple"])

    def test_gap_reset_gt_epoch(self):
        """T_gap > W."""
        fsm = self.config["fsm"]
        self.assertGreater(fsm["gap_reset_multiple"], 1)


if __name__ == "__main__":
    unittest.main()
