"""Deterministic three-host OpenFlow 1.3 topology for Stage 2.

This module is intentionally limited to a local Mininet topology. It creates no attack
traffic and has no mitigation or detection behaviour.
"""

from __future__ import annotations

from argparse import ArgumentParser

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

from networking.mininet.config import TopologyConfig

OPENFLOW_PROTOCOL = "OpenFlow13"


class Stage2Topology(Topo):
    """Create h1 (client), h2 (test host), h3 (server), and OVS switch s1."""

    def build(self) -> None:
        """Construct a deterministic, isolated star topology."""

        switch = self.addSwitch("s1", protocols=OPENFLOW_PROTOCOL, failMode="secure")
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="02:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="02:00:00:00:00:02")
        h3 = self.addHost("h3", ip="10.0.0.3/24", mac="02:00:00:00:00:03")
        self.addLink(h1, switch)
        self.addLink(h2, switch)
        self.addLink(h3, switch)


topos = {"stage2": Stage2Topology}


def create_network(config: TopologyConfig) -> Mininet:
    """Build and start the topology against an externally started Ryu controller."""

    config.validate()
    network = Mininet(
        topo=Stage2Topology(),
        controller=None,
        switch=OVSSwitch,
        autoSetMacs=False,
        build=False,
    )
    network.addController(
        "c0",
        controller=RemoteController,
        ip=config.controller_host,
        port=config.controller_port,
    )
    try:
        network.build()
        network.start()
        switch = network.get("s1")
        switch.cmd(f"ovs-vsctl set bridge s1 protocols={OPENFLOW_PROTOCOL}")
    except BaseException:
        # A supervised parent may interrupt a blocked startup with SIGINT.
        # Attempt topology cleanup for that interruption before propagating it.
        network.stop()
        raise
    return network


def main() -> None:
    """Start the local topology and offer the Mininet CLI until the user exits."""

    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--controller-host")
    parser.add_argument("--controller-port", type=int)
    arguments = parser.parse_args()
    environment = TopologyConfig.from_environment()
    config = TopologyConfig(
        controller_host=arguments.controller_host or environment.controller_host,
        controller_port=arguments.controller_port or environment.controller_port,
    )

    network = create_network(config)
    try:
        CLI(network)
    finally:
        network.stop()


if __name__ == "__main__":
    main()
