"""Production pipeline checks with real BMv2 metadata and byte-level assertions."""
import csv
import tempfile
import unittest
from pathlib import Path
from scapy.all import Ether, IP, UDP, TCP, ICMP, ARP, Raw, IPOption, wrpcap
from scapy.utils import checksum
from collector.ptt_headers import PTTShim, PTTHop, decode_ptt
from collector.parse_pcap import parse_pcap_to_csv
from control.configure_switch import configure_forwarding, configure_switch_id, run_cli
from control.configure_queues import configure_queues
from control.generate_p4_params import ROOT
from bmv2_runtime import Switch
from bmv2_conformance import packet, MACS


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sw = Switch(ROOT/"build/ptt_int.json")
        cls.addClassCleanup(cls.sw.close)

    def setUp(self):
        self.sw.reset()
        self.sw.write("switch_id",1,index=0)
        self.sw.queues.set_egress_queue_rate(1,0)
        self.sw.queues.set_egress_queue_depth(1,128)

    def check_ip(self, raw):
        parsed = Ether(raw)
        ip = parsed[IP]
        self.assertEqual(checksum(raw[14:14+ip.ihl*4]),0)
        self.assertEqual(ip.len,len(raw)-14)
        return parsed

    def test_real_metadata_and_control_plane(self):
        configure_switch_id(self.sw.port,4095)
        configure_queues(self.sw.port,128,0,[1])
        run_cli(self.sw.port,["table_set_default PttIngress.ipv4_lpm PttIngress.do_drop"])
        configure_forwarding(self.sw.port,[{"dst_ip":"10.0.0.2/32","port":1}])
        original = packet(dst="10.0.0.2",payload=b"data"*250)
        port,raw = self.sw.exchange(original)
        parsed = self.check_ip(raw)
        shim,hops,payload = decode_ptt(bytes(parsed[UDP].payload))
        self.assertEqual(port,1)
        self.assertEqual((shim.hop_count,hops[0].switch_id,hops[0].egress_port),(1,4095,1))
        self.assertEqual(hops[0].qdepth,0)
        self.assertEqual(hops[0].state,0)
        self.assertEqual(payload,b"data"*250)
        self.assertEqual(len(raw),len(bytes(original))+20)
        self.assertGreater(self.sw.read("last_epoch"),0)
        self.assertEqual(hops[0].timestamp_low,self.sw.read("last_report") & 0xFFFFFFFF)
        self.sw.send(packet(dst="10.0.0.3"))
        self.assertIsNone(self.sw.recv(100))

    def test_two_switch_append_preserve_and_collection(self):
        payload = b"application data"*40
        with Switch(ROOT/"build/ptt_int.json",switch_id=2) as second:
            _,first_raw = self.sw.exchange(packet(payload=payload))
            _,second_raw = second.exchange(first_raw)
            parsed = self.check_ip(second_raw)
            shim,hops,app = decode_ptt(bytes(parsed[UDP].payload))
            self.assertEqual(shim.hop_count,2)
            self.assertEqual([h.switch_id for h in hops],[2,1])
            self.assertEqual(app,payload)
            self.assertEqual(len(second_raw),len(first_raw)+12)
            # Within its epoch, the second switch is not due for a local sample.
            _,preserved = second.exchange(first_raw)
            self.assertEqual(bytes(Ether(preserved)[UDP]),bytes(Ether(first_raw)[UDP]))
            with tempfile.TemporaryDirectory() as d:
                pcap,output=Path(d)/"capture.pcap",Path(d)/"telemetry.csv"
                wrpcap(str(pcap),[Ether(second_raw)])
                self.assertEqual(parse_pcap_to_csv(pcap,output),(1,1))
                with output.open() as f:
                    rows=list(csv.DictReader(f))
                self.assertEqual([r["switch_id"] for r in rows],["2","1"])

    def test_nine_hops_saturate_stack_and_preserve_payload(self):
        # Recirculate through the same production program as nine independent
        # initialized ports/switch identities; wire accumulation is identical.
        raw=bytes(packet(payload=b"z"*1000))
        for hop_id in range(1,10):
            self.sw.reset()
            self.sw.write("switch_id",hop_id,index=0)
            _,raw=self.sw.exchange(raw)
            parsed=self.check_ip(raw)
        shim,hops,payload=decode_ptt(bytes(parsed[UDP].payload))
        self.assertEqual(shim.hop_count,8)
        self.assertEqual([h.switch_id for h in hops],list(range(8,0,-1)))
        self.assertEqual(shim.flags & 1,1)
        self.assertEqual(payload,b"z"*1000)
        self.assertEqual(len(raw),14+20+8+1000+104)
        self.assertEqual(self.sw.read("last_report"),0)

    def test_ipv4_options_checksum_and_payload(self):
        original=packet(options=[IPOption(b"\x01\x01\x01\x00")],payload=b"options"*30)
        _,raw=self.sw.exchange(original)
        parsed=self.check_ip(raw)
        self.assertEqual(parsed[IP].ihl,6)
        self.assertEqual(bytes(parsed[IP].options[0]),bytes(Ether(bytes(original))[IP].options[0]))
        _,_,payload=decode_ptt(bytes(parsed[UDP].payload))
        self.assertEqual(payload,b"options"*30)

    def test_non_udp_and_fragments_do_not_touch_predictor(self):
        base=Ether(**MACS)/IP(src="10.0.0.1",dst="10.0.0.2")
        packets=[
            base/TCP(sport=12345,dport=80)/Raw(b"t"*40),
            base/ICMP()/Raw(b"i"*40),
            packet(flags="MF"),
            base.copy()/Raw(b"f"*64),
        ]
        packets[-1][IP].proto=17
        packets[-1][IP].frag=1
        for original in packets:
            with self.subTest(packet=original.summary()):
                _,raw=self.sw.exchange(original)
                parsed=self.check_ip(raw)
                expected=Ether(bytes(original))
                self.assertEqual(bytes(parsed[IP].payload),bytes(expected[IP].payload))
                self.assertEqual(len(raw),len(bytes(original)))
                self.assertEqual(self.sw.read("initialized"),0)

    def test_malformed_packets_and_expired_ttl_are_dropped(self):
        good=bytes(packet())
        malformed=[
            good[:13], good[:33], good[:-1], packet(version=6), packet(ihl=4),
            packet(len=19), packet(len=60000), packet(chksum=0x1234),
            packet(ttl=0),packet(ttl=1), Ether(**MACS)/ARP(),
        ]
        for udp_len in (0,7,9,60000):
            bad=packet()
            bad[UDP].len=udp_len
            malformed.append(bad)
        for data in [
            b"",b"PT",bytes(PTTShim(magic=0)),bytes(PTTShim(version=2)),
            bytes(PTTShim(hop_count=9))+b"x"*108,
            bytes(PTTShim(hop_count=1))+b"x"*11,
        ]:
            bad=packet(payload=data)
            bad[UDP].dport=32768
            malformed.append(bad)
        for index,bad in enumerate(malformed):
            with self.subTest(case=index):
                self.sw.send(bad)
                self.assertIsNone(self.sw.recv(80))
                self.assertEqual(self.sw.read("initialized"),0)

    def test_lengths_near_ipv4_limit_do_not_wrap(self):
        for hops, payload_size, expect_inserted in [
            (None,65487,True), (None,65488,False),
            ([],65487,True), ([],65488,False),
        ]:
            with self.subTest(hops=hops,payload_size=payload_size):
                self.sw.reset()
                original=packet(payload=b"x"*payload_size,hops=hops)
                _,raw=self.sw.exchange(original)
                parsed=self.check_ip(raw)
                self.assertEqual(len(raw),len(bytes(original))+(20 if hops is None else 12)*expect_inserted)
                self.assertEqual(bool(self.sw.read("last_report")),expect_inserted)
                if expect_inserted:
                    self.assertEqual(parsed[IP].len,65535)
                    self.assertEqual(parsed[UDP].chksum,0)
                else:
                    self.assertEqual(bytes(parsed[UDP]),bytes(Ether(bytes(original))[UDP]))

    def test_ethernet_padding_is_not_telemetry_or_udp_payload(self):
        original = bytes(packet(payload=b"x"))
        padding = b"\xa5" * (60-len(original))
        _, raw = self.sw.exchange(original+padding)
        parsed = Ether(raw)
        ip = parsed[IP]
        self.assertEqual(checksum(raw[14:14+ip.ihl*4]),0)
        self.assertEqual(ip.len,len(original)-14+20)
        self.assertEqual(raw[14+ip.len:],padding)
        _,hops,payload = decode_ptt(raw[42:14+ip.len])
        self.assertEqual(len(hops),1)
        self.assertEqual(payload,b"x")

    def test_real_queue_threshold_activates_burst(self):
        # A bounded functional queue test, not a workload/performance experiment.
        # Packet-in transport still traverses the real simple_switch egress queue.
        configure_queues(self.sw.port,128,200,[1])
        for index in range(240):
            self.sw.send(packet(payload=index.to_bytes(4,"big")+b"q"*500))
        reports=[]
        received=0
        while True:
            result=self.sw.recv(900)
            if result is None:
                break
            received+=1
            parsed=self.check_ip(result[1])
            if parsed[UDP].dport==32768:
                _,hops,_=decode_ptt(bytes(parsed[UDP].payload))
                reports.append(hops[0])
        self.assertGreater(received,96)
        self.assertLessEqual(received,240)
        self.assertGreater(len(reports),0)
        self.assertGreaterEqual(max(h.qdepth for h in reports),96)
        self.assertTrue(any(h.state==2 and h.reason==3 for h in reports))
        self.assertTrue(all(h.egress_port==1 for h in reports))
