from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import networkx as nx
import random

class ControllerInLoopECMP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    STATS_INTERVAL = 2
    UTILIZATION_THRESHOLD = 50  # example threshold

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.graph = nx.DiGraph()
        self.datapaths = {}
        self.port_stats = {}
        self.mac_to_port = {}
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        self.datapaths[dp.id] = dp

        # Lowest priority rule: flood unknown packets
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
        dp.send_msg(mod)
        self.logger.info("[BOOT] Controller rule set for switch %s", dp.id)

    @set_ev_cls(event.EventSwitchEnter)
    def on_switch_enter(self, ev):
        switch_list = get_switch(self, None)
        switches = [sw.dp.id for sw in switch_list]
        self.graph.add_nodes_from(switches)

        link_list = get_link(self, None)
        for link in link_list:
            src = link.src.dpid
            dst = link.dst.dpid
            port = link.src.port_no
            self.graph.add_edge(src, dst, port=port, weight=1)

        self.logger.info("[TOPO] Topology updated: switches=%s", switches)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                parser = dp.ofproto_parser
                req = parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY)
                dp.send_msg(req)
            hub.sleep(self.STATS_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        self.port_stats[dpid] = {stat.port_no: stat.tx_bytes for stat in ev.msg.body}

    def _get_best_path(self, src, dst):
        try:
            paths = list(nx.all_shortest_paths(self.graph, src, dst))
        except nx.NetworkXNoPath:
            return []

        path_loads = []
        for path in paths:
            load = 0
            for i in range(len(path) - 1):
                sw = path[i]
                next_sw = path[i + 1]
                port = self.graph[sw][next_sw]['port']
                load += self.port_stats.get(sw, {}).get(port, 0)
            path_loads.append((load, path))

        if all(load > self.UTILIZATION_THRESHOLD for load, _ in path_loads):
            best = min(path_loads, key=lambda x: x[0])[1]
            self.logger.info("[PATH] Adaptive ECMP path: %s", best)
            return best
        else:
            chosen = random.choice(paths)
            self.logger.info("[PATH] Traditional ECMP path: %s", chosen)
            return chosen
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        src_mac = eth.src
        dst_mac = eth.dst
        self.mac_to_port.setdefault(dpid, {})[src_mac] = in_port

        # Handle ARP separately
        if arp_pkt:
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=dp,
                                    buffer_id=msg.buffer_id,
                                    in_port=in_port,
                                    actions=actions,
                                    data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
            dp.send_msg(out)
            self.logger.info("[ARP] Flooded ARP from %s to %s", src_mac, dst_mac)
            return

        # Handle IPv4 forwarding
        # Try to find the destination switch based on learned MAC table
        dst_dpid = None
        dst_port = None
        for sw_id, mac_table in self.mac_to_port.items():
            if dst_mac in mac_table:
                dst_dpid = sw_id
                dst_port = mac_table[dst_mac]
                break

        if dst_dpid is None:
            # Destination unknown, flood
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=dp,
                                    buffer_id=msg.buffer_id,
                                    in_port=in_port,
                                    actions=actions,
                                    data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
            dp.send_msg(out)
            self.logger.info("[FLOOD] Destination MAC %s unknown, flooding", dst_mac)
            return

        # Get best path from current switch to destination switch
        path = self._get_best_path(dpid, dst_dpid)
        if not path or len(path) < 2:
            self.logger.warning("[DROP] No valid path from switch %s to %s", dpid, dst_dpid)
            return

        next_hop = path[1]
        out_port = self.graph[dpid][next_hop]['port']
        actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(datapath=dp,
                                buffer_id=msg.buffer_id,
                                in_port=in_port,
                                actions=actions,
                                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        dp.send_msg(out)
        self.logger.info("[FORWARD] %s -> %s via switch %s port %s", src_mac, dst_mac, dpid, out_port)


    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def packet_in_handler(self, ev):
    #     msg = ev.msg
    #     dp = msg.datapath
    #     dpid = dp.id
    #     ofproto = dp.ofproto
    #     parser = dp.ofproto_parser
    #     in_port = msg.match['in_port']

    #     pkt = packet.Packet(msg.data)
    #     eth = pkt.get_protocol(ethernet.ethernet)
    #     ip = pkt.get_protocol(ipv4.ipv4)
    #     if not ip:
    #         return

    #     src_mac = eth.src
    #     dst_mac = eth.dst
    #     self.mac_to_port.setdefault(dpid, {})[src_mac] = in_port

    #     arp_pkt = pkt.get_protocol(arp.arp)
    #     if arp_pkt:
    #         # Learn MAC address
    #         self.mac_to_port.setdefault(dpid, {})[src_mac] = in_port

    #         # Forward the ARP packet using best path or flood
    #         if dst_mac in self.mac_to_port.get(dpid, {}):
    #             out_port = self.mac_to_port[dpid][dst_mac]
    #             actions = [parser.OFPActionOutput(out_port)]
    #         else:
    #             actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

    #         out = parser.OFPPacketOut(
    #             datapath=dp,
    #             buffer_id=msg.buffer_id,
    #             in_port=in_port,
    #             actions=actions,
    #             data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
    #         )
    #         dp.send_msg(out)
    #         self.logger.info("[ARP] Forwarded ARP from %s -> %s", src_mac, dst_mac)
    #         return


        # pkt = packet.Packet(msg.data)
        # eth = pkt.get_protocol(ethernet.ethernet)
        # ip = pkt.get_protocol(ipv4.ipv4)
        # if not ip:
        #     return

        # src_mac = eth.src
        # dst_mac = eth.dst
        # self.mac_to_port.setdefault(dpid, {})[src_mac] = in_port

        # # Find destination DPID from MAC table
        # dst_dpid = None
        # dst_port = None
        # for sw_id, mac_table in self.mac_to_port.items():
        #     if dst_mac in mac_table:
        #         dst_dpid = sw_id
        #         dst_port = mac_table[dst_mac]
        #         break

        # if dst_dpid is None or dst_port is None:
        #     self.logger.info("[FLOOD] MAC %s unknown, flooding", dst_mac)
        #     actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        #     out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
        #                               in_port=in_port, actions=actions,
        #                               data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        #     dp.send_msg(out)
        #     return

        # path = self._get_best_path(dpid, dst_dpid)
        # if not path or len(path) < 2:
        #     self.logger.warning("[DROP] No valid path from %s to %s", dpid, dst_dpid)
        #     return

        # next_hop = path[1]
        # out_port = self.graph[dpid][next_hop]['port']
        # actions = [parser.OFPActionOutput(out_port)]
        # out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
        #                           in_port=in_port, actions=actions,
        #                           data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        # dp.send_msg(out)

        # self.logger.info("[FORWARD] %s -> %s via port %s on switch %s", src_mac, dst_mac, out_port, dpid)
