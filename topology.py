#!/usr/bin/env python3
"""
Project 12: Dynamic Host Blocking System
Mininet Topology with Multiple Communicating Hosts

Topology:
  h1 (10.0.0.1) - Normal Client
  h2 (10.0.0.2) - Suspicious/Attacker Client
  h3 (10.0.0.3) - Concurrent Normal Client
  h4 (10.0.0.4) - Protected TCP Server
  All connected to Open vSwitch s1 (OpenFlow 1.3)
"""

from mininet.topo import Topo

class DynamicBlockingTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1', protocols='OpenFlow13')

        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)

topos = {'dhb': DynamicBlockingTopo}

