#!/usr/bin/env python3
"""Monitor TCP SYN rates and dynamically block excessive sources with OpenFlow."""
from collections import defaultdict, deque
import time
from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import packet, ipv4
from os_ken.ofproto import ofproto_v1_3


class HostBlocker(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    WINDOW, LIMIT, BLOCK, STATS = 5, 8, 25, 4

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dp = None
        self.syns = defaultdict(deque)
        self.blocked = {}
        hub.spawn(self.monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_ready(self, ev):
        self.dp = dp = ev.msg.datapath
        p, ofp = dp.ofproto_parser, dp.ofproto
        normal = p.OFPActionOutput(ofp.OFPP_NORMAL)
        controller = p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)
        self.flow(0, p.OFPMatch(), [normal])
        syn = p.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=(0x002, 0x012))
        self.flow(100, syn, [controller, normal])
        self.logger.info('[SWITCH] Connected: %016x', dp.id)

    def flow(self, priority, match, actions, hard_timeout=0):
        p, ofp = self.dp.ofproto_parser, self.dp.ofproto
        instructions = ([p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
                        if actions else [])
        self.dp.send_msg(p.OFPFlowMod(datapath=self.dp, priority=priority,
            match=match, instructions=instructions, hard_timeout=hard_timeout))

    def source_match(self, ip):
        return self.dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)

    def block(self, ip):
        # Switch timeout is a safety net; controller normally deletes the rule at 25 s.
        self.flow(200, self.source_match(ip), [], self.BLOCK + self.STATS)
        self.blocked[ip] = time.monotonic() + self.BLOCK
        self.logger.warning('[SDN DROP RULE] [BLOCKLIST] %s blocked for %ss', ip, self.BLOCK)

    def unblock(self, ip):
        p, ofp = self.dp.ofproto_parser, self.dp.ofproto
        self.dp.send_msg(p.OFPFlowMod(datapath=self.dp, command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, priority=200,
            match=self.source_match(ip)))

    def monitor(self):
        while True:
            now = time.monotonic()
            for ip, expiry in list(self.blocked.items()):
                if now >= expiry:
                    self.unblock(ip)
                    del self.blocked[ip]
                    self.syns[ip].clear()
                    self.logger.info('[UNBLOCK] Host %s recovered', ip)
            if self.dp:
                self.dp.send_msg(self.dp.ofproto_parser.OFPFlowStatsRequest(self.dp))
            hub.sleep(self.STATS)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        # The original SYN is forwarded by OVS; this is the controller's monitoring copy.
        ip = packet.Packet(ev.msg.data).get_protocol(ipv4.ipv4)
        if not ip or ip.src in self.blocked:
            return
        history, now = self.syns[ip.src], time.monotonic()
        history.append(now)
        while now - history[0] > self.WINDOW:
            history.popleft()
        self.logger.info('[RATE-MONITOR] %s: %s/%s SYNs', ip.src, len(history), self.LIMIT)
        if len(history) >= self.LIMIT:
            self.logger.warning('[ALERT] Suspicious host: %s', ip.src)
            self.block(ip.src)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats(self, ev):
        for flow in ev.msg.body:
            if flow.priority in (100, 200):
                self.logger.info('[FLOW-STAT] priority=%s packets=%s bytes=%s',
                                 flow.priority, flow.packet_count, flow.byte_count)
