#!/usr/bin/env python3
"""
Project 12: Dynamic Host Blocking System
SDN Controller (OpenFlow 1.3) using OS-Ken / Ryu

Mandatory Features Implemented:
1. Monitors TCP connection rates (sliding window of TCP SYN packets)
2. Defines abnormal traffic thresholds (SYN_THRESHOLD in WINDOW seconds)
3. Detects suspicious hosts exceeding the threshold
4. Maintains a dynamic blocklist with automatic cooldown expiration
5. Installs SDN drop rules (OpenFlow 1.3 priority 200 drop)
6. Collects and logs flow statistics periodically
"""

# Monkey-patch eventlet before any other module imports to prevent RLock warnings
import eventlet
eventlet.monkey_patch()

from collections import defaultdict, deque
import time

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub
from os_ken.lib.packet import (
    packet,
    ethernet,
    ether_types,
    ipv4,
    tcp,
)


class DynamicHostBlockingController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # --- Threshold & Monitoring Configuration ---
    WINDOW_SECONDS = 5.0       # Sliding observation window (seconds)
    SYN_THRESHOLD = 8          # Abnormal traffic threshold: max allowed SYNs in window
    BLOCK_DURATION = 25.0      # Duration (seconds) to block a suspicious host
    STATS_INTERVAL = 4.0       # Flow statistics polling interval (seconds)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.syn_history = defaultdict(deque)  # IP -> deque of timestamps
        self.dynamic_blocklist = {}            # IP -> unblock_timestamp
        self.datapaths = {}                    # DPID -> switch datapath object
        self.monitor_thread = hub.spawn(self._monitor_loop)

        self.logger.info("==================================================")
        self.logger.info(" Project 12: Dynamic Host Blocking SDN Controller ")
        self.logger.info(" Sliding Window: %.1fs | SYN Threshold: %d | Cooldown: %.1fs",
                         self.WINDOW_SECONDS, self.SYN_THRESHOLD, self.BLOCK_DURATION)
        self.logger.info("==================================================")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Track connected Open vSwitch datapaths."""
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("[SWITCH] Connected: DPID=%016x", dp.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install initial flow rules on switch startup."""
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        self.datapaths[dp.id] = dp

        # 1. Table-Miss Rule (Priority 0): send unhandled packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, priority=0, match=match, actions=actions)

        # 2. TCP SYN Telemetry Rule (Priority 100): trap SYN packets to monitor connection rate
        # Using mask (0x002, 0x002) so all packets with SYN bit set are intercepted
        syn_match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=6,                   # TCP
            tcp_flags=(0x002, 0x002)      # Match SYN flag
        )
        self._add_flow(dp, priority=100, match=syn_match, actions=actions)
        self.logger.info("[RULES] Initialized Table-Miss & TCP SYN monitoring on DPID=%016x", dp.id)

    def _add_flow(self, dp, priority, match, actions=None, idle_timeout=0, hard_timeout=0):
        """Send an OpenFlow FlowMod to the switch."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        instructions = []
        if actions is not None:
            instructions = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        dp.send_msg(mod)

    def install_sdn_drop_rule(self, dp, src_ip, duration):
        """Feature: Install SDN drop rule (Priority 200, empty action list = DROP)."""
        parser = dp.ofproto_parser
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip
        )
        # Empty action list instructs switch to drop all matching packets in hardware/kernel
        self._add_flow(dp, priority=200, match=match, actions=[], hard_timeout=int(duration))
        self.logger.warning(">>> [SDN DROP RULE] Installed DROP rule for %s (Priority 200) on DPID=%016x", src_ip, dp.id)

    def remove_sdn_drop_rule(self, dp, src_ip):
        """Remove drop rule when cooldown period expires."""
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip
        )
        mod = parser.OFPFlowMod(
            datapath=dp,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            priority=200,
            match=match
        )
        dp.send_msg(mod)
        self.logger.info(">>> [RECOVERY] Removed DROP rule for %s on DPID=%016x", src_ip, dp.id)

    def _record_syn_and_get_rate(self, src_ip):
        """Feature: Monitor connection rates over sliding time window."""
        now = time.time()
        history = self.syn_history[src_ip]
        history.append(now)

        # Remove timestamps older than sliding window
        while history and (now - history[0] > self.WINDOW_SECONDS):
            history.popleft()

        return len(history)

    def _check_and_expire_blocklist(self):
        """Feature: Maintain dynamic blocklist with timeout expiration."""
        now = time.time()
        for ip, expiry in list(self.dynamic_blocklist.items()):
            if now >= expiry:
                for dp in list(self.datapaths.values()):
                    self.remove_sdn_drop_rule(dp, ip)

                del self.dynamic_blocklist[ip]
                self.syn_history[ip].clear()
                self.logger.info(">>> [UNBLOCK] Host %s cooldown expired. Removed from dynamic blocklist. Traffic restored. <<<", ip)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Analyze packets, detect suspicious hosts, and install drop rules."""
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        self.datapaths[dpid] = dp
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # Drop any packet immediately if the source IP is currently in the dynamic blocklist
        if ip_pkt and ip_pkt.src in self.dynamic_blocklist:
            return

        if ip_pkt and tcp_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            # Check if this is a TCP SYN attempt (SYN=1, ACK=0)
            is_syn = bool(tcp_pkt.bits & tcp.TCP_SYN) and not bool(tcp_pkt.bits & tcp.TCP_ACK)

            if is_syn:
                rate = self._record_syn_and_get_rate(src_ip)
                self.logger.info("[RATE-MONITOR] %s -> %s | SYNs: %d/%d in %.1fs",
                                 src_ip, dst_ip, rate, self.SYN_THRESHOLD, self.WINDOW_SECONDS)

                # Feature: Detect suspicious hosts exceeding abnormal traffic threshold
                if rate >= self.SYN_THRESHOLD:
                    self.logger.critical(">>> [ALERT] SUSPICIOUS HOST DETECTED: %s (Rate: %d SYNs in %.1fs, Threshold: %d) <<<",
                                         src_ip, rate, self.WINDOW_SECONDS, self.SYN_THRESHOLD)
                    
                    # Feature: Maintain dynamic blocklist
                    self.dynamic_blocklist[src_ip] = time.time() + self.BLOCK_DURATION
                    self.logger.critical(">>> [BLOCKLIST] Added %s to dynamic blocklist for %.1fs <<<",
                                         src_ip, self.BLOCK_DURATION)

                    # Feature: Install SDN drop rules across connected switches
                    targets = list(self.datapaths.values()) if self.datapaths else [dp]
                    for switch_dp in targets:
                        self.install_sdn_drop_rule(switch_dp, src_ip, self.BLOCK_DURATION)

                    # Drop this triggering packet
                    return

        # Normal L2 learning switch forwarding
        dst = eth.dst
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        out_port = self.mac_to_port[dpid].get(dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Do not cache flow rules for SYN packets so all future SYNs are tracked
        if out_port != ofp.OFPP_FLOOD and not (ip_pkt and tcp_pkt and (tcp_pkt.bits & tcp.TCP_SYN)):
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=eth.src)
            self._add_flow(dp, priority=10, match=match, actions=actions, idle_timeout=15)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        dp.send_msg(out)

    def _monitor_loop(self):
        """Feature: Collect flow statistics and expire blocks periodically."""
        while True:
            self._check_and_expire_blocklist()

            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                req = parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)

            hub.sleep(self.STATS_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Feature: Collect flow statistics from switch."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        rules = [f for f in body if f.priority in (100, 200)]
        if rules:
            self.logger.info("--- [FLOW-STATISTICS DPID=%016x] ---", dpid)
            for flow in sorted(rules, key=lambda x: x.priority, reverse=True):
                rule_name = "SDN-DROP-RULE" if flow.priority == 200 else "SYN-MONITOR"
                try:
                    match_str = dict(flow.match.items())
                except Exception:
                    match_str = str(flow.match)
                self.logger.info("  [%s] Priority=%d | Packets=%d | Bytes=%d | Duration=%ds | Match=%s",
                                 rule_name, flow.priority, flow.packet_count, flow.byte_count,
                                 flow.duration_sec, match_str)
            self.logger.info("------------------------------------------------")
