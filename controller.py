#!/usr/bin/env python3
"""Detect excessive TCP SYN traffic and block its source with OpenFlow."""
import eventlet
eventlet.monkey_patch()
from collections import defaultdict, deque
import time
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
    DEAD_DISPATCHER, set_ev_cls)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub
from os_ken.lib.packet import packet, ethernet, ipv4, tcp, ether_types


class HostBlocker(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    WINDOW, LIMIT, BLOCK, STATS = 5, 8, 25, 4

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.switches, self.mac = {}, {}
        self.syns, self.blocked = defaultdict(deque), {}
        hub.spawn(self.monitor)
        self.logger.info("Host blocker ready: %s SYNs/%ss, block %ss",
                         self.LIMIT, self.WINDOW, self.BLOCK)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def switch_state(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.switches[dp.id] = dp
            self.logger.info("[SWITCH] Connected: %016x", dp.id)
        else:
            self.switches.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_ready(self, ev):
        dp, p = ev.msg.datapath, ev.msg.datapath.ofproto_parser
        self.switches[dp.id] = dp
        send = [p.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER,
                                  dp.ofproto.OFPCML_NO_BUFFER)]
        self.flow(dp, 0, p.OFPMatch(), send)
        syn = p.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=6,
                         tcp_flags=(tcp.TCP_SYN, tcp.TCP_SYN))
        self.flow(dp, 100, syn, send)

    def flow(self, dp, priority, match, actions, timeout=0):
        p, ofp = dp.ofproto_parser, dp.ofproto
        instructions = [p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                 instructions=instructions, hard_timeout=timeout))

    def block(self, dp, ip):
        match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        for switch in self.switches.values():
            self.flow(switch, 200, match, [], self.BLOCK)
        self.blocked[ip] = time.time() + self.BLOCK
        self.logger.warning("[SDN DROP RULE] [BLOCKLIST] %s blocked for %ss", ip, self.BLOCK)

    def unblock(self, dp, ip):
        p, ofp = dp.ofproto_parser, dp.ofproto
        match = p.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        dp.send_msg(p.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, priority=200, match=match))

    def monitor(self):
        while True:
            now = time.time()
            for ip, expiry in list(self.blocked.items()):
                if now >= expiry:
                    for dp in self.switches.values():
                        self.unblock(dp, ip)
                    del self.blocked[ip]
                    self.syns[ip].clear()
                    self.logger.info("[UNBLOCK] Host %s recovered", ip)
            for dp in self.switches.values():
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(self.STATS)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg, dp = ev.msg, ev.msg.datapath
        p, ofp = dp.ofproto_parser, dp.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        port = msg.match['in_port']
        self.mac.setdefault(dp.id, {})[eth.src] = port
        ip, segment = pkt.get_protocol(ipv4.ipv4), pkt.get_protocol(tcp.tcp)
        if ip and ip.src in self.blocked:
            return
        if ip and segment and segment.bits & tcp.TCP_SYN and not segment.bits & tcp.TCP_ACK:
            history = self.syns[ip.src]
            now = time.time()
            history.append(now)
            while history and now - history[0] > self.WINDOW:
                history.popleft()
            count = len(history)
            self.logger.info("[RATE-MONITOR] %s: %s/%s SYNs", ip.src, count, self.LIMIT)
            if count >= self.LIMIT:
                self.logger.warning("[ALERT] Suspicious host: %s", ip.src)
                self.block(dp, ip.src)
                return
        out = self.mac[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [p.OFPActionOutput(out)]
        if out != ofp.OFPP_FLOOD and not (segment and segment.bits & tcp.TCP_SYN):
            match = p.OFPMatch(in_port=port, eth_src=eth.src, eth_dst=eth.dst)
            self.flow(dp, 10, match, actions, 15)
        data = None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data
        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
            in_port=port, actions=actions, data=data))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats(self, ev):
        for f in ev.msg.body:
            if f.priority in (100, 200):
                self.logger.info("[FLOW-STAT] priority=%s packets=%s bytes=%s",
                                 f.priority, f.packet_count, f.byte_count)
