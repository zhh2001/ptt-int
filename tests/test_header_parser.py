#!/usr/bin/env python3
"""Unit tests for PTT header parsing."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collector.ptt_headers import (
    STATE_NAMES,
    REASON_NAMES,
    SCHEME_NAMES,
    parse_state_name,
    parse_reason_name,
    parse_scheme_name,
)


class TestHeaderConstants(unittest.TestCase):
    """Test header constant definitions."""

    def test_state_names(self):
        """State encoding covers QUIET, WATCH, BURST."""
        self.assertEqual(STATE_NAMES[0], "QUIET")
        self.assertEqual(STATE_NAMES[1], "WATCH")
        self.assertEqual(STATE_NAMES[2], "BURST")
        self.assertEqual(len(STATE_NAMES), 3)

    def test_reason_names(self):
        """Reason codes."""
        self.assertEqual(REASON_NAMES[0], "PERIODIC_QUIET")
        self.assertEqual(REASON_NAMES[1], "PERIODIC_WATCH")
        self.assertEqual(REASON_NAMES[2], "PREDICTIVE_NEAR")
        self.assertEqual(REASON_NAMES[3], "EMERGENCY_THRESHOLD")
        self.assertEqual(REASON_NAMES[4], "FRESHNESS")
        self.assertEqual(REASON_NAMES[5], "BASELINE_TRIGGER")

    def test_scheme_names(self):
        """Scheme mode encoding matches config."""
        self.assertEqual(SCHEME_NAMES[0], "FULL")
        self.assertEqual(SCHEME_NAMES[1], "PERIODIC_4")
        self.assertEqual(SCHEME_NAMES[2], "PERIODIC_16")
        self.assertEqual(SCHEME_NAMES[3], "PERIODIC_32")
        self.assertEqual(SCHEME_NAMES[4], "REACTIVE")
        self.assertEqual(SCHEME_NAMES[5], "DELTA")
        self.assertEqual(SCHEME_NAMES[6], "PTT")

    def test_parse_state_name(self):
        self.assertEqual(parse_state_name(0), "QUIET")
        self.assertEqual(parse_state_name(1), "WATCH")
        self.assertEqual(parse_state_name(2), "BURST")
        self.assertIn("UNKNOWN", parse_state_name(99))

    def test_parse_reason_name(self):
        self.assertEqual(parse_reason_name(0), "PERIODIC_QUIET")
        self.assertEqual(parse_reason_name(5), "BASELINE_TRIGGER")
        self.assertIn("UNKNOWN", parse_reason_name(99))


class TestPacketParsing(unittest.TestCase):
    """Integration test with scapy packet construction."""

    def test_ptt_shim_construction(self):
        """PTT shim can be constructed and parsed with scapy."""
        from scapy.all import Ether, IP, UDP, Raw
        from collector.ptt_headers import PTTShim, PTTHop, register_ptt_layers

        register_ptt_layers(int_port=32768)

        # Build a packet with PTT shim + one hop
        shim = PTTShim(magic=0x5054, original_udp_dport=65534)
        shim.version = 1
        shim.hop_count = 1

        hop = PTTHop()
        hop.switch_id = 1
        hop.egress_port = 2
        hop.state = 2
        hop.reason = 3
        hop.qdepth = 100
        hop.q_pred_far = 120
        hop.timestamp_low = 12345678

        pkt = (
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=12345, dport=32768)
            / shim
            / hop
            / Raw(b"payload")
        )

        # Serialize and parse
        data = bytes(pkt)
        pkt2 = Ether(data)

        self.assertTrue(PTTShim in pkt2)
        shim = pkt2[PTTShim]
        self.assertEqual(shim.magic, 0x5054)
        self.assertEqual(shim.version, 1)
        self.assertEqual(shim.hop_count, 1)

        self.assertTrue(PTTHop in pkt2)
        hop = pkt2[PTTHop]
        self.assertEqual(hop.switch_id, 1)
        self.assertEqual(hop.egress_port, 2)
        self.assertEqual(hop.state, 2)
        self.assertEqual(hop.reason, 3)
        self.assertEqual(hop.qdepth, 100)
        self.assertEqual(hop.q_pred_far, 120)
        self.assertEqual(hop.timestamp_low, 12345678)

    def test_multiple_hops(self):
        """Packet with multiple hop records parses correctly."""
        from scapy.all import Ether, IP, UDP, Raw
        from collector.ptt_headers import PTTShim, PTTHop, register_ptt_layers

        register_ptt_layers(int_port=32768)

        shim = PTTShim(magic=0x5054, original_udp_dport=65534)
        shim.version = 1
        shim.hop_count = 2

        hop1 = PTTHop()
        hop1.switch_id = 1
        hop1.egress_port = 2
        hop1.state = 1
        hop1.reason = 1
        hop1.qdepth = 50
        hop1.q_pred_far = 80
        hop1.timestamp_low = 1000

        hop2 = PTTHop()
        hop2.switch_id = 2
        hop2.egress_port = 1
        hop2.state = 2
        hop2.reason = 2
        hop2.qdepth = 100
        hop2.q_pred_far = 120
        hop2.timestamp_low = 2000

        pkt = (
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=12345, dport=32768)
            / shim
            / hop1
            / hop2
            / Raw(b"payload")
        )

        data = bytes(pkt)
        pkt2 = Ether(data)

        self.assertTrue(PTTShim in pkt2)
        shim = pkt2[PTTShim]
        self.assertEqual(shim.hop_count, 2)

        # Check first hop
        hop1 = pkt2[PTTHop]
        self.assertEqual(hop1.switch_id, 1)

        # Check second hop
        self.assertTrue(PTTHop in hop1.payload)
        hop2 = hop1.payload
        self.assertEqual(hop2.switch_id, 2)


if __name__ == "__main__":
    unittest.main()
