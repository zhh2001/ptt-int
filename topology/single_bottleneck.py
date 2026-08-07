#!/usr/bin/env python3
"""Single-bottleneck topology for PTT-INT experiments.

  h1 ---- s1 ---- s2 ---- h2
                 ^
             bottleneck egress (s2-eth1 -> h2)
"""

import sys
import time
import argparse
from pathlib import Path

# Add repo root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mininet.net import Mininet
from mininet.node import Host
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel


def create_single_bottleneck(
    queue_depth: int = 128,
    queue_rate: int | None = None,
    bottleneck_bw: float = 10.0,  # Mbps
    bottleneck_delay: str = "5ms",
    link_bw: float = 1000.0,  # Mbps
    link_delay: str = "1ms",
    mtu: int = 2000,
) -> Mininet:
    """Create a single-bottleneck topology.

    h1 --(1Gbps)-- s1 --(bottleneck)-- s2 --(1Gbps)-- h2

    The bottleneck is on s2's egress toward h2.
    """
    net = Mininet(link=TCLink)

    # Hosts
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")

    # Switches (BMv2)
    s1 = net.addSwitch("s1")
    s2 = net.addSwitch("s2")

    # Links
    net.addLink(h1, s1, bw=link_bw, delay=link_delay, mtu=mtu)
    net.addLink(s1, s2, bw=bottleneck_bw, delay=bottleneck_delay, mtu=mtu)
    net.addLink(s2, h2, bw=link_bw, delay=link_delay, mtu=mtu)

    return net


def main():
    parser = argparse.ArgumentParser(description="Single-bottleneck topology")
    parser.add_argument("--queue-depth", type=int, default=128)
    parser.add_argument("--queue-rate", type=int, default=None)
    parser.add_argument("--bottleneck-bw", type=float, default=10.0)
    parser.add_argument("--mtu", type=int, default=2000)
    args = parser.parse_args()

    setLogLevel("info")
    net = create_single_bottleneck(
        queue_depth=args.queue_depth,
        queue_rate=args.queue_rate,
        bottleneck_bw=args.bottleneck_bw,
        mtu=args.mtu,
    )

    try:
        net.start()
        print("Topology started. Press Ctrl+C to stop.")
        CLI(net)
    except KeyboardInterrupt:
        pass
    finally:
        net.stop()


if __name__ == "__main__":
    main()
