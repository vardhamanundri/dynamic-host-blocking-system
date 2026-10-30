#!/usr/bin/env python3
"""Four clients/server hosts connected to one OpenFlow 1.3 switch."""
from mininet.topo import Topo

class DynamicBlockingTopo(Topo):
    def build(self):
        switch = self.addSwitch('s1', protocols='OpenFlow13')
        for n in range(1, 5):
            host = self.addHost(f'h{n}', ip=f'10.0.0.{n}/24',
                                mac=f'00:00:00:00:00:0{n}')
            self.addLink(host, switch)

topos = {'dhb': DynamicBlockingTopo}
