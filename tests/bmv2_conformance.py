"""Packet-by-packet checks on the actual compiled P4 control."""
import copy
import ipaddress
import json
import random
import subprocess
import tempfile
import unittest
from pathlib import Path
import yaml
from scapy.all import Ether, IP, UDP, Raw
from scapy.utils import checksum
from collector.ptt_headers import PTTShim, PTTHop, decode_ptt
from control.generate_p4_params import ROOT, generate
from bmv2_runtime import Switch
from model import Port, CLOCK_MASK

MACS = dict(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def packet(q=0, now=1, payload=b"application payload"*4, hops=None, **ip_fields):
    fields = dict(src=str(ipaddress.IPv4Address(q)), dst=str(ipaddress.IPv4Address(now & 0xFFFFFFFF)),
                  id=now >> 32, ttl=64)
    fields.update(ip_fields)
    dport = 9999
    if hops is not None:
        payload = bytes(PTTShim(hop_count=len(hops), hops=hops, original_udp_dport=9999)) + payload
        dport = 32768
    return Ether(**MACS) / IP(**fields) / UDP(sport=12345, dport=dport) / Raw(payload)


def compile_adapter(output, config):
    generate(config, Path(output) / "generated_params.p4")
    dest = Path(output) / "deterministic.json"
    subprocess.run(["p4c-bm2-ss", "--std", "p4-16", "-I", str(output), "-I", str(ROOT/"p4src"),
                    "-o", str(dest), str(ROOT/"tests/p4/deterministic.p4")],
                   check=True, capture_output=True, text=True)
    return dest


class ConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = yaml.safe_load((ROOT/"config/default.yaml").read_text())
        cls.tmp = tempfile.TemporaryDirectory(prefix="ptt-compile-")
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.binary = compile_adapter(cls.tmp.name, ROOT/"config/default.yaml")
        cls.sw = Switch(cls.binary)
        cls.addClassCleanup(cls.sw.close)

    def setUp(self):
        self.sw.reset()
        self.model = Port()

    def assert_registers(self, model=None, port=1):
        for name, value in (model or self.model).registers().items():
            self.assertEqual(self.sw.read(name, port), value, (name, port))

    def step(self, q, now, model=None, port=1, hops=None, payload=b"PTT payload"*10):
        model = model or self.model
        can_insert = hops is None or len(hops) < self.cfg["packet"]["max_hops"]
        emit, reason, far = model.step(q, now, self.cfg, can_insert)
        source = packet(q, now, payload=payload, hops=hops)
        self.sw.forward(port)
        eport, raw = self.sw.exchange(source)
        self.assertEqual(eport, port)
        output = Ether(raw)
        ip, udp = output[IP], output[UDP]
        self.assertEqual(ip.ttl, 63)
        self.assertEqual(checksum(raw[14:14+ip.ihl*4]), 0)
        old_count = 0 if hops is None else len(hops)
        inserted = emit and can_insert
        added = (20 if hops is None else 12) if inserted else 0
        self.assertEqual(len(raw), len(bytes(source)) + added)
        self.assertEqual(ip.len, len(raw)-14)
        self.assertEqual(udp.len, ip.len-ip.ihl*4)
        if hops is not None or inserted:
            shim, records, app = decode_ptt(bytes(udp.payload))
            self.assertEqual(shim.hop_count, old_count + int(inserted))
            self.assertEqual(shim.original_udp_dport, 9999)
            self.assertEqual(app, payload)
            if inserted:
                hop = records[0]
                self.assertEqual((hop.switch_id, hop.egress_port, hop.state, hop.reason),
                                 (1, port, model.state, reason))
                self.assertEqual((hop.qdepth, hop.q_pred_far, hop.timestamp_low),
                                 (q, far, now & 0xFFFFFFFF))
                self.assertEqual(udp.chksum, 0)
            if hops is not None:
                self.assertEqual([bytes(h) for h in records[int(inserted):]], [bytes(h) for h in hops])
            self.assertEqual(bool(shim.flags & 1), emit and not can_insert)
        else:
            self.assertEqual(udp.dport, 9999)
            self.assertEqual(bytes(udp.payload), payload)
        self.assert_registers(model, port)
        return inserted, reason, output

    def seed(self, **values):
        self.model = Port(**values)
        for name, value in self.model.registers().items():
            self.sw.write(name, value)

    def test_register_inventory_matches_table_3(self):
        data = json.loads(self.binary.read_text())
        regs = {r["name"].split(".")[-1]:(r["bitwidth"], r["size"]) for r in data["register_arrays"]}
        expected = {"prev_q_reg":(32,512), "trend_q8_reg":(32,512), "last_epoch_reg":(48,512),
                    "state_reg":(2,512), "recovery_count_reg":(8,512), "sample_counter_reg":(32,512),
                    "last_report_reg":(48,512), "initialized_reg":(1,512), "switch_id_reg":(12,1)}
        self.assertEqual(regs, expected)
        self.assertEqual(sum(w for n,(w,s) in regs.items() if s == 512), 203)

    def test_first_packet_and_quiet_sampling_phase(self):
        selected = [i for i in range(65) if self.step(0, i+1)[0]]
        self.assertEqual(selected, [0, 32, 64])

    def test_known_growth_watch_burst_and_recovery(self):
        states, growth = [], []
        for index, q in enumerate([0,20,40,60,70,80,96]):
            self.step(q, 1+index*5000)
            states.append(self.model.state)
            growth.append(self.model.trend_q8)
        self.assertEqual(states, [0,0,1,1,1,2,2])
        self.assertEqual(growth, [0,1280,2240,2960,2860,2785,3113])
        # Clear growth through a gap, then six lower-target epochs recover one level at a time.
        now = 60002
        self.step(0, now)
        recovery = []
        for _ in range(6):
            now += 5000
            self.step(0, now)
            recovery.append(self.model.state)
        self.assertEqual(recovery, [2,2,1,1,1,0])

    def test_epoch_boundary_and_reactive_threshold(self):
        self.step(96, 1)
        self.assertEqual(self.model.state, 0)
        self.step(96, 5000)
        self.assertEqual(self.model.state, 0)
        self.step(96, 5001)
        self.assertEqual(self.model.state, 2)
        self.assertEqual(self.model.trend_q8, 0)
        self.step(0, 5002)
        self.assertEqual(self.model.state, 2)

    def test_projection_equality_and_q8_decay(self):
        # Starting from zero history: G=64*q, qN=floor(1.5*q), qF=3*q.
        for q, expected in [(31,0), (32,1), (63,1), (64,2)]:
            with self.subTest(q=q):
                self.seed(initialized=1,last_epoch=1)
                self.step(q,5001)
                self.assertEqual(self.model.state,expected)
        self.seed(initialized=1,last_epoch=1,prev_q=20,trend_q8=7)
        self.step(0,5001)
        self.assertEqual(self.model.trend_q8,6)
        self.step(0,10001)
        self.assertEqual(self.model.trend_q8,5)

    def test_gap_and_idle_boundaries_preserve_recovery(self):
        for elapsed, q, state, recovery in [
            (20000,0,1,0), (20001,0,2,2), (99999,0,2,2),
            (100000,63,0,0), (100000,64,2,2), (100001,96,2,2),
        ]:
            with self.subTest(elapsed=elapsed, q=q):
                self.seed(initialized=1, state=2, recovery_count=2, last_epoch=1,
                          last_report=1, sample_counter=1)
                self.step(q, elapsed+1)
                self.assertEqual((self.model.state,self.model.recovery_count), (state,recovery))

    def test_equal_or_higher_target_cancels_recovery(self):
        self.seed(initialized=1, state=1, recovery_count=2, prev_q=80, trend_q8=2048, last_epoch=1)
        self.step(80,5001)  # far=128; target WATCH equals committed state
        self.assertEqual((self.model.state,self.model.recovery_count), (1,0))
        self.seed(initialized=1, state=1, recovery_count=2, prev_q=96, last_epoch=1)
        self.step(96,5001)
        self.assertEqual((self.model.state,self.model.recovery_count), (2,0))

    def test_watch_mask_and_counter_wrap(self):
        self.seed(initialized=1, state=1, last_epoch=1, last_report=1)
        selected = [i for i in range(16) if self.step(0,i+2)[0]]
        self.assertEqual(selected, [0,4,8,12])
        self.seed(initialized=1, sample_counter=0xFFFFFFFF, last_epoch=1, last_report=1)
        self.assertFalse(self.step(0,2)[0])
        self.assertTrue(self.step(0,3)[0])
        self.assertEqual(self.model.sample_counter,1)

    def test_freshness_boundary_and_timestamp_wrap(self):
        self.seed(initialized=1, sample_counter=1, last_epoch=99999, last_report=1)
        self.assertFalse(self.step(0,100000)[0])
        inserted, reason, _ = self.step(0,100001)
        self.assertTrue(inserted)
        self.assertEqual(reason,4)
        self.seed(initialized=1, sample_counter=1, last_epoch=CLOCK_MASK-1999, last_report=CLOCK_MASK-99999)
        self.step(20,3000)
        self.assertEqual(self.model.trend_q8,1280)
        self.assertEqual(self.model.last_epoch,3000)

    def test_full_stack_does_not_advance_freshness(self):
        hops = [PTTHop(switch_id=i, timestamp_low=i) for i in range(8)]
        self.step(0,1,hops=hops)
        self.assertEqual(self.model.last_report,0)
        self.step(0,100000,hops=hops)
        self.assertEqual(self.model.last_report,0)
        inserted, reason, _ = self.step(0,100001)
        self.assertTrue(inserted)
        self.assertEqual(reason,4)

    def test_append_preserve_and_max_hops(self):
        for count in range(9):
            with self.subTest(count=count):
                self.sw.reset()
                self.model = Port()
                hops = [PTTHop(switch_id=i+10) for i in range(count)]
                self.step(0,1,hops=hops)
                # Not selected: downstream PTT payload must be identical.
                self.step(0,2,hops=hops)

    def test_port_isolation_and_full_width_queue_arithmetic(self):
        ports = {1:Port(),2:Port(),510:Port()}
        for index in range(12):
            for port, model in ports.items():
                q = (0x7FFFF if index % 2 else 0) if port == 510 else index*8 if port == 1 else 0
                self.step(q,1+index*5000,model=model,port=port)
        self.assertEqual(ports[2].state,0)
        self.assertEqual(ports[510].state,2)

    def test_seeded_random_trace(self):
        rng = random.Random(220926)
        now = 1
        for index in range(350):
            now = (now + rng.choice([0,1,4999,5000,5001,20000,20001,99999,100000])) & CLOCK_MASK
            q = rng.choice([0,1,63,64,95,96,97,127,128,0x7FFFF,rng.randrange(129)])
            with self.subTest(packet=index, q=q, now=now):
                self.step(q,now)

    def test_alternate_configuration_is_executed(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["predictor"].update(epoch_us=1000, ewma_alpha_shift=3, near_horizon=4, far_horizon=16)
        cfg["fsm"]["recovery_epochs"] = 2
        cfg["sampling"].update(quiet_mask=15,watch_mask=1)
        cfg["packet"]["max_hops"] = 4
        with tempfile.TemporaryDirectory() as d:
            config = Path(d)/"alternate.yaml"
            config.write_text(yaml.safe_dump(cfg))
            binary = compile_adapter(d,config)
            previous_sw, previous_cfg = self.sw, self.cfg
            with Switch(binary) as sw:
                self.sw, self.cfg = sw, cfg
                try:
                    self.model = Port()
                    for index,q in enumerate([0,20,40,60,80,96,0,0,0,0,0]):
                        self.step(q,1+index*1000)
                    self.step(0,12001,hops=[PTTHop() for _ in range(4)])
                finally:
                    self.sw,self.cfg = previous_sw,previous_cfg
