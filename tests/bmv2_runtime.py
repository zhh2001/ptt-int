"""Isolated BMv2 instances using packet-in sockets; no root or host network changes."""
import json
import errno
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

try:
    import nnpy
    from thrift.protocol import TBinaryProtocol, TMultiplexedProtocol
    from thrift.transport import TSocket, TTransport
    from bm_runtime.standard import Standard
    from sswitch_runtime import SimpleSwitch
except ImportError as exc:
    raise RuntimeError(
        "BMv2 tests require nnpy, thrift and the BMv2 Python modules. "
        "Use the Python environment installed with BMv2, or set PYTHONPATH to its site-packages."
    ) from exc


class Switch:
    def __init__(self, json_path, switch_id=1):
        self.tmp = tempfile.TemporaryDirectory(prefix="ptt-test-")
        self.process = self.transport = self.packet_socket = None
        self.log = None
        try:
            self.config = json.loads(Path(json_path).read_text())
            self.regs = {r["name"].split(".")[-1]: r["name"] for r in self.config["register_arrays"]}
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                self.port = sock.getsockname()[1]
            path = Path(self.tmp.name)
            addr = "ipc://" + str(path / "packets.ipc")
            self.log = open(path / "switch.log", "w+")
            self.process = subprocess.Popen([
                "simple_switch", "--packet-in", addr, "--thrift-port", str(self.port),
                "--notifications-addr", "ipc://" + str(path / "notifications.ipc"),
                "--log-level", "warn", str(Path(json_path).resolve()),
            ], stdout=self.log, stderr=self.log)
            deadline = time.monotonic() + 10
            while True:
                # Avoid Thrift's noisy connection-refused logging during startup.
                if self.process.poll() is not None:
                    self.log.seek(0)
                    raise RuntimeError(self.log.read())
                try:
                    with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("BMv2 Thrift startup timed out")
                    time.sleep(0.02)
            raw = TSocket.TSocket("127.0.0.1", self.port)
            raw.setTimeout(3000)
            self.transport = TTransport.TBufferedTransport(raw)
            protocol = TBinaryProtocol.TBinaryProtocol(self.transport)
            self.client = Standard.Client(TMultiplexedProtocol.TMultiplexedProtocol(protocol, "standard"))
            self.queues = SimpleSwitch.Client(TMultiplexedProtocol.TMultiplexedProtocol(protocol, "simple_switch"))
            self.transport.open()
            self.packet_socket = nnpy.Socket(nnpy.AF_SP, nnpy.PAIR)
            self.packet_socket.setsockopt(nnpy.SOL_SOCKET, nnpy.RCVTIMEO, 2000)
            self.packet_socket.setsockopt(nnpy.SOL_SOCKET, nnpy.SNDTIMEO, 2000)
            self.packet_socket.connect(addr)
            self.write("switch_id", switch_id, index=0)
            self.forward(1)
        except BaseException:
            self.close()
            raise

    def forward(self, port):
        self.client.bm_mt_set_default_action(
            0, "PttIngress.ipv4_lpm", "PttIngress.forward", [port.to_bytes(2, "big")])

    def read(self, name, index=1):
        return self.client.bm_register_read(0, self.regs[name + "_reg"], index)

    def write(self, name, value, index=1):
        self.client.bm_register_write(0, self.regs[name + "_reg"], index, value)

    def reset(self):
        for name in self.regs:
            if name != "switch_id_reg":
                self.client.bm_register_reset(0, self.regs[name])
        self.forward(1)

    def send(self, packet, port=0):
        data = bytes(packet)
        self.packet_socket.send(struct.pack("=iii", 3, port, len(data)) + data)

    def recv(self, timeout_ms=2000):
        self.packet_socket.setsockopt(nnpy.SOL_SOCKET, nnpy.RCVTIMEO, timeout_ms)
        try:
            msg = self.packet_socket.recv()
        except nnpy.NNError as exc:
            if exc.error_no == errno.ETIMEDOUT:
                return None
            raise
        kind, port, size = struct.unpack("=iii", msg[:12])
        if kind != 4 or len(msg) != size + 12:
            raise AssertionError("invalid BMv2 packet-out message")
        return port, msg[12:]

    def exchange(self, packet):
        self.send(packet)
        output = self.recv()
        if output is None:
            raise AssertionError("BMv2 failed to forward an expected packet")
        return output

    def close(self):
        if self.packet_socket is not None:
            self.packet_socket.close()
        if self.transport is not None:
            self.transport.close()
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        if self.log is not None:
            self.log.close()
        self.tmp.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
