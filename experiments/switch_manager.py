#!/usr/bin/env python3
"""SwitchManager: BMv2 simple_switch orchestration with veth pairs + ip netns.

NO Mininet dependency.  Uses the same low-level primitives as tests/test_smoke.py:
veth pairs, ip netns, static ARP (nud permanent), simple_switch subprocess.Popen,
and simple_switch_CLI for Thrift-based configuration.

Three topologies are supported out of the box:
  1. single_bottleneck  – h1---s1---s2---h2, bottleneck on s2 egress port 1
  2. incast              – N senders -> s1 -> s2 -> receiver, bottleneck on s2 egress
  3. leaf_spine          – 2x2 (default) leaf-spine fabric, bottleneck on spine->leaf egress
"""

import os
import sys
import time
import signal
import shutil
import subprocess
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Low-level helpers  (module-private, same conventions as test_smoke.py)
# ---------------------------------------------------------------------------

def _run(cmd, **kwargs):
    """Thin wrapper around subprocess.run with safe defaults."""
    kwargs.setdefault("text", True)
    kwargs.setdefault("timeout", 30)
    kwargs.setdefault("capture_output", True)
    return subprocess.run(cmd, **kwargs)


def _kill_gentle(pid):
    """SIGTERM, brief wait, then SIGKILL a process by pid."""
    if pid is None:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, OSError):
        return
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass
    time.sleep(0.3)
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass


# ---------------------------------------------------------------------------
# SwitchManager
# ---------------------------------------------------------------------------

class SwitchManager:
    """Orchestrate BMv2 simple_switch processes with veth-based topologies.

    The caller is assumed to already have root privileges; this class never
    calls sudo.  All topology setup uses subprocess.run (synchronous / blocking);
    only the long-running simple_switch processes are launched via
    subprocess.Popen and tracked by pid.

    Typical usage::

        mgr = SwitchManager(tmpdir="/tmp/my_exp", p4_json_path="p4src/ptt_int.json")
        topo = mgr.create_single_bottleneck()

        for sw_name, sw_cfg in topo["switches"].items():
            mgr.start_switch(sw_name, **sw_cfg)
            mgr.wait_thrift(sw_cfg["thrift_port"])

        mgr.configure_switch(9090, 1, 6, [{"dst_ip": "10.0.0.2/32", "port": 1}])
        mgr.set_queue(9091, 1, 128, 100)

        # ... run traffic ...

        mgr.stop_all()
    """

    # -- ports / ids --------------------------------------------------------

    _THRIFT_BASE = 9090
    _DEVICE_ID_BASE = 0

    # -- public interface ---------------------------------------------------

    def __init__(self, tmpdir: str, p4_json_path: str):
        """Create a SwitchManager bound to a working directory.

        Args:
            tmpdir: Top-level temporary directory for logs, pcaps, and
                    other per-run artifacts.  Will be created if missing.
            p4_json_path: Absolute or relative path to the compiled P4 JSON
                          (e.g. ``p4src/ptt_int.json``).
        """
        self._tmpdir = Path(tmpdir)
        self._p4_json = str(p4_json_path)

        os.makedirs(self._tmpdir, exist_ok=True)

        # Pid bookkeeping
        self._pids: dict[str, int] = {}
        self._procs: dict[str, subprocess.Popen] = {}

        # Cleanup bookkeeping
        self._veths: list[str] = []
        self._namespaces: list[str] = []

        # Logs & pcaps (base path -> actual path)
        self._log_paths: dict[str, str] = {}
        self._pcap_dirs: dict[str, str] = {}

        self._next_thrift = self._THRIFT_BASE
        self._next_device_id = self._DEVICE_ID_BASE

    # ------------------------------------------------------------------
    # Topology creation
    # ------------------------------------------------------------------

    def create_single_bottleneck(self) -> dict:
        """Return the canonical single-bottleneck topology dict.

        Topology::

            h1 --- s1 --- s2 --- h2
                            ^
                        bottleneck egress (s2 port 1 -> h2)

        Switches:  s1 (9090, id 0),  s2 (9091, id 1)
        Hosts:     h1 (10.0.0.1/24), h2 (10.0.0.2/24)
        """
        self._reset_counters()

        # -- 1.  Namespaces -------------------------------------------------
        ns_h1, ns_h2 = "ptt_ns_h1", "ptt_ns_h2"
        for ns in (ns_h1, ns_h2):
            _run(["ip", "netns", "add", ns], check=True)
            self._namespaces.append(ns)
            _run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])

        # -- 2.  Veth pairs -------------------------------------------------
        # switch-side , host-side
        veth_pairs = [
            ("s1_h1", "h1_s1"),
            ("s1_s2", "s2_s1"),
            ("s2_h2", "h2_s2"),
        ]
        for sw_iface, host_iface in veth_pairs:
            self._create_veth_pair(sw_iface, host_iface)

        # Bring up switch-side and inter-switch interfaces (in root namespace)
        _run(["ip", "link", "set", "s1_h1", "up"])
        _run(["ip", "link", "set", "s1_s2", "up"])
        _run(["ip", "link", "set", "s2_s1", "up"])
        _run(["ip", "link", "set", "s2_h2", "up"])

        # -- 3.  Host setup -------------------------------------------------
        self._setup_host_basic("h1", "10.0.0.1/24", ns_h1, "h1_s1", "s1_h1")
        self._setup_host_basic("h2", "10.0.0.2/24", ns_h2, "h2_s2", "s2_h2")

        h1_mac = self._get_iface_mac(ns_h1, "h1_s1")
        h2_mac = self._get_iface_mac(ns_h2, "h2_s2")

        self._set_host_arp(ns_h1, "h1_s1", [("10.0.0.2", h2_mac)])
        self._set_host_arp(ns_h2, "h2_s2", [("10.0.0.1", h1_mac)])

        return {
            "name": "single_bottleneck",
            "switches": {
                "s1": {
                    "thrift_port": 9090,
                    "device_id": 0,
                    "interfaces": [
                        (0, "s1_h1"),
                        (1, "s1_s2"),
                    ],
                },
                "s2": {
                    "thrift_port": 9091,
                    "device_id": 1,
                    "interfaces": [
                        (0, "s2_s1"),
                        (1, "s2_h2"),
                    ],
                },
            },
            "hosts": {
                "h1": {
                    "ns": ns_h1,
                    "ip": "10.0.0.1/24",
                    "iface": "h1_s1",
                    "mac": h1_mac,
                    "peer_iface": "s1_h1",
                },
                "h2": {
                    "ns": ns_h2,
                    "ip": "10.0.0.2/24",
                    "iface": "h2_s2",
                    "mac": h2_mac,
                    "peer_iface": "s2_h2",
                },
            },
            "bottleneck": {"switch": "s2", "port": 1},
            "links": [("h1", "h2")],
        }

    def create_incast(self, n_senders: int = 4) -> dict:
        """Return an incast topology dict.

        Topology::

            h1 ─┐
            h2 ─┤
            ...  ├── s1 ── s2 ── receiver
            hN ─┘              ^
                        bottleneck egress (s2 port 1 -> receiver)

        Args:
            n_senders: Number of sending hosts (default 4).
        """
        self._reset_counters()

        if n_senders < 1:
            raise ValueError("n_senders must be >= 1")

        # -- 1.  Namespaces -------------------------------------------------
        ns_names = {}
        for i in range(1, n_senders + 1):
            ns = f"ptt_ns_h{i}"
            ns_names[f"h{i}"] = ns
            _run(["ip", "netns", "add", ns], check=True)
            self._namespaces.append(ns)
            _run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])

        recv_ns = "ptt_ns_recv"
        ns_names["receiver"] = recv_ns
        _run(["ip", "netns", "add", recv_ns], check=True)
        self._namespaces.append(recv_ns)
        _run(["ip", "netns", "exec", recv_ns, "ip", "link", "set", "lo", "up"])

        # -- 2.  Veth pairs -------------------------------------------------
        # s1 <-> each sender
        sender_pairs = []
        for i in range(1, n_senders + 1):
            sw_iface = f"s1_h{i}"
            host_iface = f"h{i}_s1"
            self._create_veth_pair(sw_iface, host_iface)
            sender_pairs.append((sw_iface, host_iface))

        # s1 <-> s2
        self._create_veth_pair("s1_s2", "s2_s1")

        # s2 <-> receiver
        self._create_veth_pair("s2_recv", "recv_s2")

        # Bring up ALL switch-side interfaces in root namespace
        for sw_iface, _host_iface in sender_pairs:
            _run(["ip", "link", "set", sw_iface, "up"])
        _run(["ip", "link", "set", "s1_s2", "up"])
        _run(["ip", "link", "set", "s2_s1", "up"])
        _run(["ip", "link", "set", "s2_recv", "up"])

        # -- 3.  Host setup -------------------------------------------------
        hosts_info = {}
        macs = {}

        for i in range(1, n_senders + 1):
            name = f"h{i}"
            ip = f"10.0.0.{i}/24"
            ns = ns_names[name]
            host_iface = f"h{i}_s1"
            sw_iface = f"s1_h{i}"
            self._setup_host_basic(name, ip, ns, host_iface, sw_iface)
            macs[name] = self._get_iface_mac(ns, host_iface)
            hosts_info[name] = {
                "ns": ns,
                "ip": ip,
                "iface": host_iface,
                "mac": macs[name],
                "peer_iface": sw_iface,
            }

        # Receiver
        recv_ip = "10.0.0.254/24"
        recv_host_iface = "recv_s2"
        recv_sw_iface = "s2_recv"
        self._setup_host_basic("receiver", recv_ip, recv_ns, recv_host_iface, recv_sw_iface)
        recv_mac = self._get_iface_mac(recv_ns, recv_host_iface)
        hosts_info["receiver"] = {
            "ns": recv_ns,
            "ip": recv_ip,
            "iface": recv_host_iface,
            "mac": recv_mac,
            "peer_iface": recv_sw_iface,
        }

        # -- 4.  Static ARP -------------------------------------------------
        for i in range(1, n_senders + 1):
            name = f"h{i}"
            info = hosts_info[name]
            self._set_host_arp(info["ns"], info["iface"],
                               [("10.0.0.254", recv_mac)])

        recv_arp_entries = []
        for i in range(1, n_senders + 1):
            recv_arp_entries.append((f"10.0.0.{i}", macs[f"h{i}"]))
        self._set_host_arp(recv_ns, recv_host_iface, recv_arp_entries)

        # -- 5.  Switch interface lists -------------------------------------
        # s1: ports 0..N-1 = senders, port N = link to s2
        s1_interfaces = []
        for i in range(n_senders):
            s1_interfaces.append((i, f"s1_h{i + 1}"))
        s1_interfaces.append((n_senders, "s1_s2"))

        # s2: port 0 = link from s1, port 1 = receiver
        s2_interfaces = [(0, "s2_s1"), (1, "s2_recv")]

        # -- 6.  Links ------------------------------------------------------
        links = [(f"h{i}", "receiver") for i in range(1, n_senders + 1)]

        return {
            "name": "incast",
            "switches": {
                "s1": {
                    "thrift_port": 9090,
                    "device_id": 0,
                    "interfaces": s1_interfaces,
                },
                "s2": {
                    "thrift_port": 9091,
                    "device_id": 1,
                    "interfaces": s2_interfaces,
                },
            },
            "hosts": hosts_info,
            "bottleneck": {"switch": "s2", "port": 1},
            "links": links,
        }

    def create_leaf_spine(self, n_leaf: int = 2, n_spine: int = 2) -> dict:
        """Return a leaf-spine topology dict.

        Topology (default 2x2)::

            h1 ── leaf0 ──┬── spine0 ──┬── leaf1 ── h2
                          └── spine1 ──┘
                                ^
                    bottleneck on spine0 egress port 0 -> leaf0

        Each leaf connects to every spine.  One host is placed behind each
        leaf by default.

        Args:
            n_leaf:  Number of leaf switches (default 2).
            n_spine: Number of spine switches (default 2).
        """
        self._reset_counters()

        if n_leaf < 1 or n_spine < 1:
            raise ValueError("n_leaf and n_spine must be >= 1")

        # -- 1.  Namespaces -------------------------------------------------
        ns_names = {}
        for i in range(1, n_leaf + 1):
            ns = f"ptt_ns_h{i}"
            ns_names[f"h{i}"] = ns
            _run(["ip", "netns", "add", ns], check=True)
            self._namespaces.append(ns)
            _run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])

        # -- 2.  Veth pairs -------------------------------------------------
        # leaf <-> host
        leaf_host_pairs = []
        for i in range(n_leaf):
            leaf_idx = i
            host_idx = i + 1
            sw_iface = f"leaf{leaf_idx}_h{host_idx}"
            host_iface = f"h{host_idx}_leaf{leaf_idx}"
            self._create_veth_pair(sw_iface, host_iface)
            leaf_host_pairs.append((leaf_idx, sw_iface, host_iface))

        # leaf <-> spine interconnects
        spine_leaf_pairs = []
        for leaf_idx in range(n_leaf):
            for spine_idx in range(n_spine):
                sw_iface = f"leaf{leaf_idx}_spine{spine_idx}"
                host_iface = f"spine{spine_idx}_leaf{leaf_idx}"
                self._create_veth_pair(sw_iface, host_iface)
                spine_leaf_pairs.append((leaf_idx, spine_idx, sw_iface, host_iface))

        # Bring up switch-side interfaces
        for _, sw_iface, _ in leaf_host_pairs:
            _run(["ip", "link", "set", sw_iface, "up"])
        for _, _, sw_iface, _ in spine_leaf_pairs:
            _run(["ip", "link", "set", sw_iface, "up"])

        # -- 3.  Host setup -------------------------------------------------
        hosts_info = {}
        for leaf_idx, sw_iface, host_iface in leaf_host_pairs:
            host_num = leaf_idx + 1
            name = f"h{host_num}"
            ip = f"10.0.0.{host_num}/24"
            ns = ns_names[name]
            self._setup_host_basic(name, ip, ns, host_iface, sw_iface)
            mac = self._get_iface_mac(ns, host_iface)
            hosts_info[name] = {
                "ns": ns,
                "ip": ip,
                "iface": host_iface,
                "mac": mac,
                "peer_iface": sw_iface,
            }

        # -- 4.  Static ARP (full mesh between all hosts) -------------------
        for name_i, info_i in hosts_info.items():
            arp_entries = []
            for name_j, info_j in hosts_info.items():
                if name_i == name_j:
                    continue
                ip_j = info_j["ip"].split("/")[0]
                arp_entries.append((ip_j, info_j["mac"]))
            if arp_entries:
                self._set_host_arp(info_i["ns"], info_i["iface"], arp_entries)

        # -- 5.  Switch interface lists -------------------------------------
        switches = {}
        thrift_base = self._next_thrift  # should be 9090 after _reset_counters
        dev_id = self._next_device_id    # should be 0

        # Leaf switches
        for leaf_idx in range(n_leaf):
            sw_name = f"leaf{leaf_idx}"
            interfaces = []
            port_idx = 0

            # host port
            for _lidx, sw_iface, _host_iface in leaf_host_pairs:
                if _lidx == leaf_idx:
                    interfaces.append((port_idx, sw_iface))
                    port_idx += 1
                    break

            # uplinks to spines
            for _lidx, _sidx, sw_iface, _host_iface in spine_leaf_pairs:
                if _lidx == leaf_idx:
                    interfaces.append((port_idx, sw_iface))
                    port_idx += 1

            switches[sw_name] = {
                "thrift_port": thrift_base + leaf_idx,
                "device_id": dev_id + leaf_idx,
                "interfaces": interfaces,
            }

        # Spine switches
        spine_dev_offset = n_leaf
        for spine_idx in range(n_spine):
            sw_name = f"spine{spine_idx}"
            interfaces = []
            port_idx = 0
            for _lidx, _sidx, sw_iface, _host_iface in spine_leaf_pairs:
                if _sidx == spine_idx:
                    # The spine-side interface name is the "host" side of
                    # the pair we created, but it stays in root ns.  Actually,
                    # the spine uses the interface that's named
                    # spine{spine_idx}_leaf{leaf_idx} which is the second
                    # name in the pair.  Wait — re-check the convention.
                    #
                    # We called _create_veth_pair("leaf{L}_spine{S}", "spine{S}_leaf{L}").
                    # The *switch-side* for a spine is spine{S}_leaf{L},
                    # which is the SECOND name returned by _create_veth_pair.
                    # But we stored them as (leaf_idx, spine_idx, sw_iface, host_iface)
                    # where sw_iface = "leaf{L}_spine{S}" and host_iface = "spine{S}_leaf{L}".
                    #
                    # For spines, the interface the spine uses is "spine{S}_leaf{L}",
                    # which is host_iface in our tuple.  BUT we also need to bring
                    # it up — we only brought up sw_iface above.  Let's fix that
                    # by also bringing up host_iface for spine pairs.
                    #
                    # Actually, _create_veth_pair brings up both sides by default
                    # via self._veths tracking... wait, no, we already brought up
                    # switch-side only above.  For the spine switches, the
                    # interface they use (spine{S}_leaf{L}) is the *peer* of the
                    # leaf's uplink.  We need to bring it up too since it stays
                    # in root ns.
                    interfaces.append((port_idx, _host_iface))
                    port_idx += 1

            switches[sw_name] = {
                "thrift_port": thrift_base + spine_dev_offset + spine_idx,
                "device_id": dev_id + spine_dev_offset + spine_idx,
                "interfaces": interfaces,
            }

        # Bring up spine interfaces  (they are in root ns)
        for spine_idx in range(n_spine):
            for _lidx, _sidx, _sw_iface, host_iface in spine_leaf_pairs:
                if _sidx == spine_idx:
                    _run(["ip", "link", "set", host_iface, "up"])

        # -- 6.  Links ------------------------------------------------------
        host_names = list(hosts_info.keys())
        links = []
        for i in range(len(host_names)):
            for j in range(i + 1, len(host_names)):
                links.append((host_names[i], host_names[j]))

        # Bottleneck: spine0 egress port 0 (toward leaf0)
        return {
            "name": "leaf_spine",
            "switches": switches,
            "hosts": hosts_info,
            "bottleneck": {"switch": "spine0", "port": 0},
            "links": links,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _create_veth_pair(self, prefix_a: str, prefix_b: str) -> tuple:
        """Create a veth pair and track both ends for cleanup.

        Args:
            prefix_a: Name for one end of the pair.
            prefix_b: Name for the other end.

        Returns:
            ``(prefix_a, prefix_b)`` tuple (same order as passed in).
        """
        _run(["ip", "link", "add", prefix_a, "type", "veth", "peer", "name", prefix_b],
             check=True)
        self._veths.append(prefix_a)
        self._veths.append(prefix_b)
        return (prefix_a, prefix_b)

    def _setup_host_basic(self, name: str, ip: str, ns_name: str,
                          host_iface: str, switch_iface: str) -> None:
        """Move a host-side veth into its namespace, assign IP, bring up.

        This is the "phase 1" of host creation — it does NOT set ARP entries
        because those may depend on other hosts' MAC addresses that are not
        yet known.
        """
        # Move host-side interface into the namespace
        _run(["ip", "link", "set", host_iface, "netns", ns_name], check=True)

        # Assign IP
        _run(["ip", "netns", "exec", ns_name,
              "ip", "addr", "add", ip, "dev", host_iface], check=True)

        # Bring up inside the namespace
        _run(["ip", "netns", "exec", ns_name,
              "ip", "link", "set", host_iface, "up"], check=True)

    def _get_iface_mac(self, ns: str, iface: str) -> str:
        """Read the MAC address of *iface* from inside namespace *ns*."""
        r = _run(["ip", "netns", "exec", ns, "cat",
                  f"/sys/class/net/{iface}/address"])
        return r.stdout.strip()

    def _set_host_arp(self, ns: str, iface: str,
                      entries: list[tuple[str, str]]) -> None:
        """Install static (nud permanent) ARP entries in a namespace.

        Args:
            ns: Namespace name.
            iface: Interface the ARP entry is bound to.
            entries: List of ``(target_ip, lladdr)`` tuples.
        """
        for target_ip, lladdr in entries:
            _run(["ip", "netns", "exec", ns,
                  "ip", "neigh", "replace", target_ip,
                  "lladdr", lladdr, "dev", iface, "nud", "permanent"],
                 check=True)

    def _reset_counters(self):
        """Reset thrift-port and device-id counters before building a topology."""
        self._next_thrift = self._THRIFT_BASE
        self._next_device_id = self._DEVICE_ID_BASE

    @staticmethod
    def _cli_cmd(thrift_port: int, commands: list[str],
                 timeout: float = 10.0) -> subprocess.CompletedProcess:
        """Execute one or more commands via simple_switch_CLI."""
        input_str = "\n".join(commands) + "\n"
        return _run(
            ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
            input=input_str,
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Switch lifecycle
    # ------------------------------------------------------------------

    def start_switch(self, name: str, thrift_port: int, device_id: int,
                     interfaces: list[tuple[int, str]]) -> subprocess.Popen:
        """Launch a simple_switch process.

        Args:
            name: Human-readable switch name (used for log/pcap paths).
            thrift_port: Thrift server port.
            device_id: BMv2 device id.
            interfaces: List of ``(port_index, veth_name)`` tuples.

        Returns:
            The ``subprocess.Popen`` instance for the running switch.

        Raises:
            RuntimeError: If the switch process dies immediately.
        """
        # Build -i arguments
        iface_args = []
        for port_idx, veth_name in interfaces:
            iface_args.extend(["-i", f"{port_idx}@{veth_name}"])

        # Log file (BMv2 appends .txt to whatever we give it)
        log_base = str(self._tmpdir / f"{name}.log")
        log_actual = log_base + ".txt"
        self._log_paths[name] = log_actual

        # Pcap directory (MUST exist before starting simple_switch)
        pcap_dir = str(self._tmpdir / f"pcap_{name}")
        os.makedirs(pcap_dir, exist_ok=True)
        self._pcap_dirs[name] = pcap_dir

        cmd = [
            "simple_switch",
            "--log-file", log_base,
            "--log-level", "info",
            *iface_args,
            "--thrift-port", str(thrift_port),
            "--device-id", str(device_id),
            "--pcap", pcap_dir,
            self._p4_json,
        ]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        # Give the process a moment to fail fast (invalid JSON, etc.)
        time.sleep(0.3)
        if proc.poll() is not None:
            stderr = ""
            try:
                stderr = proc.stderr.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            raise RuntimeError(
                f"simple_switch '{name}' exited immediately with code "
                f"{proc.returncode}.\nstderr: {stderr}"
            )

        self._pids[name] = proc.pid
        self._procs[name] = proc
        return proc

    def wait_thrift(self, thrift_port: int, timeout: float = 15.0) -> None:
        """Block until the Thrift server on *thrift_port* is ready.

        Readiness is determined by successfully reading the switch_id_reg
        register via simple_switch_CLI.

        Args:
            thrift_port: Thrift server port.
            timeout: Maximum seconds to wait.

        Raises:
            RuntimeError: If the Thrift server does not respond in time.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = _run(
                ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
                input="register_read switch_id_reg 0\n",
                timeout=5,
            )
            if r.returncode == 0:
                return
            time.sleep(0.5)
        raise RuntimeError(
            f"Thrift server on port {thrift_port} did not become ready "
            f"within {timeout}s"
        )

    def stop_all(self) -> None:
        """Kill all simple_switch processes, delete veth pairs and namespaces.

        Cleanup order: kill switches (fast), delete veths (fast), delete
        namespaces (fast).  Individual failures are logged but do not prevent
        cleanup of remaining resources.
        """
        # 1.  Kill switch processes
        for name in list(self._pids.keys()):
            pid = self._pids.pop(name, None)
            _kill_gentle(pid)
        self._procs.clear()

        # 2.  Delete veths  (deleting one end deletes the pair)
        # We track both ends in _veths; attempting to delete the second end
        # after the pair is gone is harmless — just ignore errors.
        for veth in self._veths:
            _run(["ip", "link", "delete", veth], timeout=5, check=False)
        self._veths.clear()

        # 3.  Delete namespaces
        for ns in self._namespaces:
            _run(["ip", "netns", "delete", ns], timeout=5, check=False)
        self._namespaces.clear()

        # 4.  Clear log/pcap bookkeeping
        self._log_paths.clear()
        self._pcap_dirs.clear()

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure_switch(self, thrift_port: int, switch_id: int,
                         scheme_mode: int, routes: list[dict]) -> None:
        """Install switch-id, scheme-mode, and LPM forwarding rules.

        Args:
            thrift_port: Thrift server port.
            switch_id: Switch identifier written to ``switch_id_reg``.
            scheme_mode: Value written to ``scheme_mode_reg``
                         (0=FULL, 1=PERIODIC_4, 2=PERIODIC_16, 3=PERIODIC_32,
                         4=REACTIVE, 5=DELTA, 6=PTT).
            routes: List of ``{"dst_ip": prefix, "port": int}`` dicts.
        """
        cmds = [
            f"register_write switch_id_reg 0 {switch_id}",
            f"register_write scheme_mode_reg 0 {scheme_mode}",
        ]
        if cmds:
            self._cli_cmd(thrift_port, cmds)

        route_cmds = []
        for route in routes:
            route_cmds.append(
                f"table_add ipv4_lpm forward {route['dst_ip']} => {route['port']}"
            )
        if route_cmds:
            self._cli_cmd(thrift_port, route_cmds)

    def set_queue(self, thrift_port: int, port: int,
                  depth: int, rate: int = 0) -> None:
        """Configure egress queue depth and rate on a single port.

        Args:
            thrift_port: Thrift server port.
            port: Egress port index.
            depth: Maximum queue depth in packets.
            rate: Service rate in packets per second (0 = unlimited).
        """
        # NOTE: BMv2 CLI syntax is "set_queue_depth <nb_pkts> [<port> [<priority>]]"
        # and "set_queue_rate <rate_pps> [<port> [<priority>]]" — value FIRST, port second!
        self._cli_cmd(thrift_port, [
            f"set_queue_depth {depth} {port}",
            f"set_queue_rate {rate} {port}",
        ])

    def read_register(self, thrift_port: int, reg_name: str,
                      index: int = 0) -> Optional[int]:
        """Read a single register value via simple_switch_CLI.

        Args:
            thrift_port: Thrift server port.
            reg_name: Register name as it appears in the P4 program.
            index: Register index (default 0).

        Returns:
            Integer register value, or ``None`` if parsing fails.
        """
        r = _run(
            ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
            input=f"register_read {reg_name} {index}\n",
        )
        out = r.stdout + r.stderr
        for line in out.splitlines():
            if f"{reg_name}[{index}]" in line and "= " in line:
                try:
                    return int(line.rsplit("= ", 1)[-1].strip())
                except ValueError:
                    pass
        return None

    # ------------------------------------------------------------------
    # Gate B: sampling counter registers
    # ------------------------------------------------------------------

    def read_sampling_counters(self, thrift_port: int, port: int) -> dict:
        """Read all Gate B sampling-counter registers for an egress port.

        Registers read:
          - eligible_quiet_reg
          - eligible_watch_reg
          - eligible_burst_reg
          - sampled_quiet_reg
          - sampled_watch_reg
          - sampled_burst_reg
          - freshness_forced_reg

        Args:
            thrift_port: Thrift server port.
            port: Egress port index to query.

        Returns:
            Dict with keys ``eligible_quiet``, ``eligible_watch``,
            ``eligible_burst``, ``sampled_quiet``, ``sampled_watch``,
            ``sampled_burst``, ``freshness_forced``.  Values are integers
            or ``None`` if a register could not be read.
        """
        reg_map = {
            "eligible_quiet_reg":     "eligible_quiet",
            "eligible_watch_reg":     "eligible_watch",
            "eligible_burst_reg":     "eligible_burst",
            "sampled_quiet_reg":      "sampled_quiet",
            "sampled_watch_reg":      "sampled_watch",
            "sampled_burst_reg":      "sampled_burst",
            "freshness_forced_reg":   "freshness_forced",
        }

        result = {}
        for reg_name, key_name in reg_map.items():
            result[key_name] = self.read_register(thrift_port, reg_name, port)
        return result

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_log_path(self, switch_name: str) -> str:
        """Return the ACTUAL log-file path for *switch_name*.

        Because BMv2 appends ``.txt`` to the ``--log-file`` argument, this
        returns the path that actually exists on disk (e.g.
        ``/tmp/exp/s1.log.txt``).
        """
        return self._log_paths.get(switch_name, "")

    def get_pcap_dir(self, switch_name: str) -> str:
        """Return the pcap output directory for *switch_name*."""
        return self._pcap_dirs.get(switch_name, "")
