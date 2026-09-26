import csv
import random
import struct
import tempfile
import unittest
from pathlib import Path
from scapy.all import Ether, IP, UDP, Raw, wrpcap
from collector.ptt_headers import PTTShim, PTTHop, decode_ptt, register_ptt_layers
from collector.parse_pcap import parse_pcap_to_csv


def wire(hops=(), payload=b"", **kwargs):
    return bytes(PTTShim(hop_count=len(hops), hops=list(hops), original_udp_dport=9999, **kwargs)) + payload


class CollectorTests(unittest.TestCase):
    def test_exact_network_order_layout(self):
        hop = PTTHop(switch_id=0xABC, egress_port=0x123, state=2, reason=4,
                     qdepth=0x45678, q_pred_far=0x12345, timestamp_low=0xDEADBEEF)
        value = 0
        for width, field in [(12, 0xABC), (9, 0x123), (2, 2), (3, 4),
                             (19, 0x45678), (19, 0x12345), (32, 0xDEADBEEF)]:
            value = value * 2**width + field
        self.assertEqual(bytes(hop), value.to_bytes(12, "big"))
        shim = PTTShim(hop_count=1, flags=1, original_udp_dport=9999)
        self.assertEqual(bytes(shim), struct.pack("!HBBHH", 0x5054, 0x11, 1, 9999, 0))
        self.assertEqual(len(bytes(PTTHop())), 12)
        self.assertEqual(len(bytes(PTTShim())), 8)

    def test_all_counts_and_payload_boundaries(self):
        for count in range(9):
            for length in (0, 1, 11, 12, 13, 24, 1000):
                with self.subTest(count=count, payload_bytes=length):
                    hops = [PTTHop(switch_id=i) for i in range(count)]
                    payload = b"\xff" * length
                    shim, parsed, data = decode_ptt(wire(hops, payload))
                    self.assertEqual(shim.hop_count, count)
                    self.assertEqual([h.switch_id for h in parsed], list(range(count)))
                    self.assertEqual(data, payload)

    def test_random_field_roundtrips(self):
        rng = random.Random(927)
        fields = {"switch_id":12, "egress_port":9, "state":2, "reason":3,
                  "qdepth":19, "q_pred_far":19, "timestamp_low":32}
        for _ in range(100):
            values = {k:rng.randrange(1 << w) for k,w in fields.items()}
            parsed = PTTHop(bytes(PTTHop(**values)))
            self.assertEqual({k:getattr(parsed, k) for k in fields}, values)

    def test_invalid_and_truncated_encapsulation(self):
        data = wire([PTTHop(), PTTHop()])
        bad = [data[:n] for n in range(len(data))]
        bad += [wire(magic=0), wire(version=2), bytes(PTTShim(hop_count=9)) + b"x"*108]
        for packet in bad:
            with self.assertRaises(ValueError):
                decode_ptt(packet)
        with self.assertRaises(ValueError):
            decode_ptt(data, max_hops=1)

    def test_scapy_binding_stops_at_declared_count(self):
        register_ptt_layers()
        payload = bytes(PTTHop(switch_id=4095)) * 20
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP() / UDP(dport=32768) / Raw(wire([PTTHop(switch_id=7)], payload))
        parsed = Ether(bytes(packet))
        self.assertEqual(len(parsed[PTTShim].hops), 1)
        self.assertEqual(bytes(parsed[PTTShim].payload), payload)

    def test_csv_ignores_payload_and_malformed_packets(self):
        base = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP() / UDP(dport=32768)
        valid = base / Raw(wire([PTTHop(switch_id=2), PTTHop(switch_id=1)], b"x"*1000, flags=1))
        invalid = base / Raw(wire([PTTHop()], magic=0))
        wrongport = base.copy()
        wrongport[UDP].dport = 12345
        wrongport /= Raw(wire([PTTHop()]))
        fragment = valid.copy()
        fragment[IP].flags = "MF"
        with tempfile.TemporaryDirectory() as d:
            pcap, output = Path(d)/"input.pcap", Path(d)/"samples.csv"
            wrpcap(str(pcap), [valid, invalid, wrongport, fragment])
            self.assertEqual(parse_pcap_to_csv(pcap, output), (4, 1))
            with output.open() as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)
            self.assertEqual([r["switch_id"] for r in rows], ["2", "1"])
            self.assertEqual(rows[0]["overflow"], "1")
            self.assertNotIn("scheme", rows[0])
