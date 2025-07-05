# # import eventlet
# # eventlet.monkey_patch()

# # from ryu.base import app_manager
# # from ryu.controller import ofp_event
# # from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
# # from ryu.ofproto import ofproto_v1_3
# # from ryu.topology import event
# # from ryu.topology.api import get_link, get_switch
# # from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, arp
# # import hashlib
# # import networkx as nx


# # class ECMPTraditional(app_manager.RyuApp):
# #     OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

# #     def __init__(self, *args, **kwargs):
# #         super(ECMPTraditional, self).__init__(*args, **kwargs)
# #         self.mac_to_port = {}    # {dpid: {mac: port}}
# #         self.datapaths = {}
# #         self.graph = nx.DiGraph()
# #         self.topo_ports = {}     # {dpid: [egress ports]}

# #     @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
# #     def switch_features_handler(self, ev):
# #         dp = ev.msg.datapath
# #         self.datapaths[dp.id] = dp
# #         parser = dp.ofproto_parser
# #         ofproto = dp.ofproto

# #         # Default low-priority flood rule
# #         match = parser.OFPMatch()
# #         actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
# #         self.add_flow(dp, 0, match, actions)

# #         self.logger.info("[BOOT] Switch %s connected", dp.id)

# #     def add_flow(self, datapath, priority, match, actions):
# #         parser = datapath.ofproto_parser
# #         ofproto = datapath.ofproto
# #         inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
# #         mod = parser.OFPFlowMod(datapath=datapath,
# #                                 priority=priority,
# #                                 match=match,
# #                                 instructions=inst)
# #         datapath.send_msg(mod)
# #         self.logger.info("[FLOW] Installed on DPID %s: %s -> %s", datapath.id, match, actions)

# #     def hash_ecmp(self, pkt):
# #         ip_pkt = pkt.get_protocol(ipv4.ipv4)
# #         tcp_pkt = pkt.get_protocol(tcp.tcp)
# #         udp_pkt = pkt.get_protocol(udp.udp)

# #         if not ip_pkt:
# #             return None

# #         five_tuple = f"{ip_pkt.src}-{ip_pkt.dst}"
# #         if tcp_pkt:
# #             five_tuple += f"-{tcp_pkt.src_port}-{tcp_pkt.dst_port}"
# #         elif udp_pkt:
# #             five_tuple += f"-{udp_pkt.src_port}-{udp_pkt.dst_port}"

# #         return int(hashlib.sha256(five_tuple.encode()).hexdigest(), 16)

# #     @set_ev_cls(event.EventLinkAdd)
# #     def link_add_handler(self, ev):
# #         self.logger.info("[TOPO] Link discovered, rebuilding topology")
# #         links = get_link(self, None)
# #         switches = get_switch(self, None)
# #         self.graph.clear()

# #         for sw in switches:
# #             self.graph.add_node(sw.dp.id)

# #         for link in links:
# #             src = link.src.dpid
# #             dst = link.dst.dpid
# #             port = link.src.port_no
# #             self.graph.add_edge(src, dst, port=port, weight=1)
# #             self.logger.info("[TOPO] %s → %s via port %s", src, dst, port)

# #     @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
# #     def packet_in_handler(self, ev):
# #         msg = ev.msg
# #         dp = msg.datapath
# #         dpid = dp.id
# #         parser = dp.ofproto_parser
# #         ofproto = dp.ofproto

# #         pkt = packet.Packet(msg.data)
# #         eth = pkt.get_protocol(ethernet.ethernet)
# #         ip_pkt = pkt.get_protocol(ipv4.ipv4)
# #         arp_pkt = pkt.get_protocol(arp.arp)

# #         src = eth.src
# #         dst = eth.dst
# #         in_port = msg.match['in_port']

# #         # Learn the source MAC
# #         self.mac_to_port.setdefault(dpid, {})
# #         self.mac_to_port[dpid][src] = in_port

# #         # Handle ARP - flood
# #         if arp_pkt:
# #             self.logger.info("[ARP] Flooding ARP request from %s", src)
# #             actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
# #             out = parser.OFPPacketOut(datapath=dp,
# #                                       buffer_id=ofproto.OFP_NO_BUFFER,
# #                                       in_port=in_port,
# #                                       actions=actions,
# #                                       data=msg.data)
# #             dp.send_msg(out)
# #             return

# #         # Find which switch knows the destination MAC
# #         dst_dpid = None
# #         dst_port = None
# #         for sw, mac_table in self.mac_to_port.items():
# #             if dst in mac_table:
# #                 dst_dpid = sw
# #                 dst_port = mac_table[dst]
# #                 break

# #         if dst_dpid is None or ip_pkt is None:
# #             # Flood if destination unknown or non-IP
# #             self.logger.info("[FLOOD] DPID %s → Destination MAC %s unknown", dpid, dst)
# #             actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
# #             out = parser.OFPPacketOut(datapath=dp,
# #                                       buffer_id=ofproto.OFP_NO_BUFFER,
# #                                       in_port=in_port,
# #                                       actions=actions,
# #                                       data=msg.data)
# #             dp.send_msg(out)
# #             return

# #         # Find all shortest paths from src_dpid to dst_dpid
# #         try:
# #             paths = list(nx.all_shortest_paths(self.graph, dpid, dst_dpid))
# #         except nx.NetworkXNoPath:
# #             self.logger.warning("[DROP] No path from %s to %s", dpid, dst_dpid)
# #             return

# #         if not paths:
# #             self.logger.warning("[DROP] No ECMP paths found")
# #             return

# #         # Hash and select ECMP path
# #         hash_val = self.hash_ecmp(pkt)
# #         if hash_val is None:
# #             return

# #         selected_path = paths[hash_val % len(paths)]
# #         self.logger.info("[ECMP] Path selected %s → %s: %s", src, dst, selected_path)

# #         # Install flows along the path
# #         for i in range(len(selected_path) - 1):
# #             curr_sw = selected_path[i]
# #             next_sw = selected_path[i + 1]
# #             out_port = self.graph[curr_sw][next_sw]['port']
# #             datapath = self.datapaths[curr_sw]
# #             p = datapath.ofproto_parser
# #             match = p.OFPMatch(eth_src=src, eth_dst=dst)
# #             actions = [p.OFPActionOutput(out_port)]
# #             inst = [p.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
# #             mod = p.OFPFlowMod(datapath=datapath,
# #                                priority=10,
# #                                match=match,
# #                                instructions=inst)
# #             datapath.send_msg(mod)
# #             self.logger.info("[FLOW] %s: %s → %s via port %s", curr_sw, src, dst, out_port)

# #         # Send the current packet out immediately
# #         out_port = self.graph[dpid][selected_path[1]]['port']
# #         actions = [parser.OFPActionOutput(out_port)]
# #         out = parser.OFPPacketOut(datapath=dp,
# #                                   buffer_id=ofproto.OFP_NO_BUFFER,
# #                                   in_port=in_port,
# #                                   actions=actions,
# #                                   data=msg.data)
# #         dp.send_msg(out)
# #         self.logger.info("[FORWARD] Sent packet from %s to %s via port %s", src, dst, out_port)


# import eventlet
# eventlet.monkey_patch()

# from ryu.base import app_manager
# from ryu.controller import ofp_event
# from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
# from ryu.ofproto import ofproto_v1_3
# from ryu.topology import event
# from ryu.topology.api import get_link, get_switch
# from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, arp
# import hashlib
# import networkx as nx


# class ECMPTraditional(app_manager.RyuApp):
#     OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

#     def __init__(self, *args, **kwargs):
#         super(ECMPTraditional, self).__init__(*args, **kwargs)
#         self.mac_to_port = {}    # {dpid: {mac: port}}
#         self.datapaths = {}      # {dpid: datapath}
#         self.graph = nx.DiGraph()

#     @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
#     def switch_features_handler(self, ev):
#         dp = ev.msg.datapath
#         self.datapaths[dp.id] = dp
#         parser = dp.ofproto_parser
#         ofproto = dp.ofproto

#         # Default low-priority controller rule
#         match = parser.OFPMatch()
#         actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
#         self.add_flow(dp, 0, match, actions)

#         self.logger.info("[BOOT] Switch %s connected", dp.id)

#     def add_flow(self, datapath, priority, match, actions):
#         parser = datapath.ofproto_parser
#         ofproto = datapath.ofproto
#         inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
#         mod = parser.OFPFlowMod(datapath=datapath,
#                                 priority=priority,
#                                 match=match,
#                                 instructions=inst)
#         datapath.send_msg(mod)
#         self.logger.info("[FLOW] Installed on DPID %s: %s -> %s", datapath.id, match, actions)

#     def hash_ecmp(self, pkt):
#         ip_pkt = pkt.get_protocol(ipv4.ipv4)
#         tcp_pkt = pkt.get_protocol(tcp.tcp)
#         udp_pkt = pkt.get_protocol(udp.udp)

#         if not ip_pkt:
#             return None

#         five_tuple = f"{ip_pkt.src}-{ip_pkt.dst}"
#         if tcp_pkt:
#             five_tuple += f"-{tcp_pkt.src_port}-{tcp_pkt.dst_port}"
#         elif udp_pkt:
#             five_tuple += f"-{udp_pkt.src_port}-{udp_pkt.dst_port}"

#         return int(hashlib.sha256(five_tuple.encode()).hexdigest(), 16)

#     @set_ev_cls(event.EventLinkAdd)
#     def link_add_handler(self, ev):
#         self.logger.info("[TOPO] Link discovered, rebuilding topology")
#         links = get_link(self, None)
#         switches = get_switch(self, None)
#         self.graph.clear()

#         for sw in switches:
#             self.graph.add_node(sw.dp.id)

#         for link in links:
#             src = link.src.dpid
#             dst = link.dst.dpid
#             port = link.src.port_no
#             self.graph.add_edge(src, dst, port=port, weight=1)
#             self.logger.info("[TOPO] %s → %s via port %s", src, dst, port)

#     @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
#     def packet_in_handler(self, ev):
#         msg = ev.msg
#         dp = msg.datapath
#         dpid = dp.id
#         parser = dp.ofproto_parser
#         ofproto = dp.ofproto

#         pkt = packet.Packet(msg.data)
#         eth = pkt.get_protocol(ethernet.ethernet)
#         ip_pkt = pkt.get_protocol(ipv4.ipv4)
#         arp_pkt = pkt.get_protocol(arp.arp)

#         src = eth.src
#         dst = eth.dst
#         in_port = msg.match['in_port']

#         self.mac_to_port.setdefault(dpid, {})
#         self.mac_to_port[dpid][src] = in_port

#         # ARP packets: flood
#         if arp_pkt:
#             self.logger.info("[ARP] Flooding ARP request from %s", src)
#             actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
#             out = parser.OFPPacketOut(datapath=dp,
#                                       buffer_id=ofproto.OFP_NO_BUFFER,
#                                       in_port=in_port,
#                                       actions=actions,
#                                       data=msg.data)
#             dp.send_msg(out)
#             return

#         # Get destination switch
#         dst_dpid = None
#         for sw_id, macs in self.mac_to_port.items():
#             if dst in macs:
#                 dst_dpid = sw_id
#                 break

#         if dst_dpid is None or ip_pkt is None:
#             self.logger.info("[FLOOD] Unknown destination (%s), flooding", dst)
#             actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
#             out = parser.OFPPacketOut(datapath=dp,
#                                       buffer_id=ofproto.OFP_NO_BUFFER,
#                                       in_port=in_port,
#                                       actions=actions,
#                                       data=msg.data)
#             dp.send_msg(out)
#             return

#         # ✅ Safeguard: skip if graph not ready
#         if dpid not in self.graph or dst_dpid not in self.graph:
#             self.logger.warning("[SKIP] Graph not ready for dpid=%s or dst_dpid=%s", dpid, dst_dpid)
#             return

#         try:
#             paths = list(nx.all_shortest_paths(self.graph, dpid, dst_dpid))
#         except nx.NetworkXNoPath:
#             self.logger.warning("[DROP] No path from %s to %s", dpid, dst_dpid)
#             return

#         if not paths:
#             self.logger.warning("[DROP] No ECMP paths found")
#             return

#         hash_val = self.hash_ecmp(pkt)
#         if hash_val is None:
#             return

#         selected_path = paths[hash_val % len(paths)]
#         self.logger.info("[ECMP] Selected path %s → %s: %s", src, dst, selected_path)

#         # Install flows on the path
#         for i in range(len(selected_path) - 1):
#             curr = selected_path[i]
#             next = selected_path[i + 1]
#             out_port = self.graph[curr][next]['port']
#             dpath = self.datapaths[curr]
#             p = dpath.ofproto_parser
#             match = p.OFPMatch(eth_src=src, eth_dst=dst)
#             actions = [p.OFPActionOutput(out_port)]
#             inst = [p.OFPInstructionActions(dpath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
#             mod = p.OFPFlowMod(datapath=dpath, priority=10, match=match, instructions=inst)
#             dpath.send_msg(mod)
#             self.logger.info("[FLOW] Installed on %s: %s → %s via port %s", curr, src, dst, out_port)

#         # Forward original packet
#         out_port = self.graph[dpid][selected_path[1]]['port']
#         actions = [parser.OFPActionOutput(out_port)]
#         out = parser.OFPPacketOut(datapath=dp,
#                                   buffer_id=ofproto.OFP_NO_BUFFER,
#                                   in_port=in_port,
#                                   actions=actions,
#                                   data=msg.data)
#         dp.send_msg(out)
#         self.logger.info("[FORWARD] Sent packet %s → %s via port %s", src, dst, out_port)


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import packet, ethernet, ipv4
import networkx as nx
import random


class ECMPTraditional(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ECMPTraditional, self).__init__(*args, **kwargs)
        self.graph = nx.DiGraph()
        self.mac_to_port = {}
        self.datapaths = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Default rule to flood unknown traffic (e.g. ARP)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("[BOOT] Default FLOOD rule installed on switch %s", datapath.id)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology(self, ev):
        switch_list = get_switch(self, None)
        switches = [sw.dp.id for sw in switch_list]
        self.graph.add_nodes_from(switches)
        self.logger.info("[TOPO] Switches: %s", switches)

        link_list = get_link(self, None)
        for link in link_list:
            src = link.src.dpid
            dst = link.dst.dpid
            port = link.src.port_no
            self.graph.add_edge(src, dst, port=port, weight=1)
            self.logger.info("[TOPO] Link added: %s -> %s via port %s", src, dst, port)

    def _get_ecmp_path(self, src, dst):
        try:
            paths = list(nx.all_shortest_paths(self.graph, src, dst))
        except nx.NetworkXNoPath:
            return []

        chosen_path = random.choice(paths)
        self.logger.info("[PATH] ECMP paths from %s to %s: %s -> chosen: %s", src, dst, paths, chosen_path)
        return chosen_path

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return

        dst_mac = eth.dst
        src_mac = eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Find destination location
        dst_dpid = None
        for sw_id, mac_table in self.mac_to_port.items():
            if dst_mac in mac_table:
                dst_dpid = sw_id
                break

        if dst_dpid is None:
            self.logger.info("[MAC_LOOKUP] Unknown destination MAC %s — flooding", dst_mac)
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            )
            datapath.send_msg(out)
            return

        # Compute ECMP path
        path = self._get_ecmp_path(dpid, dst_dpid)
        if not path or len(path) < 2:
            self.logger.warning("[PATH] No valid ECMP path found from %s to %s", dpid, dst_dpid)
            return

        # Install flow rules along path
        for i in range(len(path) - 1):
            curr_sw = path[i]
            next_sw = path[i + 1]
            out_port = self.graph[curr_sw][next_sw]['port']
            dp = self.datapaths[curr_sw]
            match = dp.ofproto_parser.OFPMatch(eth_dst=dst_mac)
            actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
            inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = dp.ofproto_parser.OFPFlowMod(datapath=dp, priority=10,
                                               match=match, instructions=inst)
            dp.send_msg(mod)
            self.logger.info("[FLOW] ECMP rule: sw=%s dst_mac=%s -> port %s", curr_sw, dst_mac, out_port)

        # Forward current packet
        out_port = self.graph[dpid][path[1]]['port']
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)
        self.logger.info("[FORWARD] Packet forwarded from %s to %s via port %s", src_mac, dst_mac, out_port)
