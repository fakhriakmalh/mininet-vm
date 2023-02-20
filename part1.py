#!/usr/bin/python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.cli import CLI


class part1_topo(Topo):
    def build(self):
        # Add hosts and switches
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')
        switch1 = self.addSwitch('s1')

        # Add links
        self.addLink(switch1, host1)
        self.addLink(switch1, host2)
        self.addLink(switch1, host3)
        self.addLink(switch1, host4)

topos = {"topo_part1": (part1_topo)}

if __name__ == "__main__":
    t = part1_topo()
    net = Mininet(topo=t)
    net.start()
    CLI(net)
    net.stop()
