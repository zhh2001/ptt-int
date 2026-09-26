import copy
import tempfile
import unittest
from pathlib import Path
import yaml
from control.generate_p4_params import ROOT, generate, parameters


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.cfg = yaml.safe_load((ROOT / "config/default.yaml").read_text())

    def test_defaults(self):
        p = parameters(self.cfg)
        self.assertEqual((p["Q_CAP"], p["Q_EVENT"], p["Q_RELEASE"]), (128, 96, 64))
        self.assertEqual((p["EPOCH_US"], p["GAP_RESET_US"], p["IDLE_RESET_US"]), (5000, 20000, 100000))
        self.assertEqual((p["EWMA_ALPHA_SHIFT"], p["EWMA_DELTA_SHIFT"], p["NEAR_SHIFT"], p["FAR_SHIFT"]), (2, 6, 7, 5))
        self.assertEqual((p["RECOVERY_EPOCHS"], p["QUIET_MASK"], p["WATCH_MASK"], p["MAX_SILENCE_US"]), (3, 31, 3, 100000))

    def test_generated_file_and_custom_parameters(self):
        self.cfg["predictor"].update(epoch_us=1000, ewma_alpha_shift=3, near_horizon=4, far_horizon=16)
        self.cfg["packet"]["max_hops"] = 4
        with tempfile.TemporaryDirectory() as d:
            source, dest = Path(d) / "config.yaml", Path(d) / "params.p4"
            source.write_text(yaml.safe_dump(self.cfg))
            p = generate(source, dest)
            self.assertIn("#define EPOCH_US 1000", dest.read_text())
            self.assertEqual((p["EWMA_DELTA_SHIFT"], p["NEAR_SHIFT"], p["FAR_SHIFT"]), (5, 6, 4))
            self.assertEqual(p["IDLE_RESET_US"], 100000)

    def test_reject_invalid_values(self):
        invalid = [
            ("queue", "capacity_packets", 524288), ("queue", "capacity_packets", 95),
            ("queue", "release_threshold_packets", 96), ("queue", "event_threshold_packets", 0),
            ("predictor", "epoch_us", 0), ("predictor", "epoch_us", True),
            ("predictor", "epoch_us", 1.5), ("predictor", "ewma_alpha_shift", 0),
            ("predictor", "ewma_alpha_shift", 9), ("predictor", "near_horizon", 3),
            ("predictor", "far_horizon", 2), ("predictor", "far_horizon", 512),
            ("fsm", "recovery_epochs", 256), ("fsm", "recovery_epochs", 0),
            ("fsm", "gap_reset_multiple", 1), ("fsm", "idle_reset_us", 20000),
            ("sampling", "quiet_mask", 30), ("sampling", "watch_mask", 63),
            ("freshness", "max_silence_us", 1 << 47),
            ("packet", "int_port", 0), ("packet", "max_hops", 9),
        ]
        for section, key, value in invalid:
            with self.subTest(section=section, key=key, value=value):
                cfg = copy.deepcopy(self.cfg)
                cfg[section][key] = value
                with self.assertRaises(ValueError):
                    parameters(cfg)

    def test_reject_unknown_or_missing_settings(self):
        for cfg in (None, {}, {**self.cfg, "experiment": {}}):
            with self.assertRaises(ValueError):
                parameters(cfg)
        self.cfg["packet"]["unused_setting"] = 123
        with self.assertRaises(ValueError):
            parameters(self.cfg)
