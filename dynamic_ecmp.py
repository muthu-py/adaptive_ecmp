# from ryu.base import app_manager
# from ryu.controller import ofp_event
# from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
# from ryu.controller.handler import set_ev_cls
# from ryu.ofproto import ofproto_v1_3
# from ryu.topology import event
# from ryu.topology.api import get_switch, get_link
# from ryu.lib.packet import packet, ethernet, ipv4
# from ryu.lib import hub
# import networkx as nx
# import random

# class DynamicECMP(app_manager.RyuApp):
#     OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
#     STATS_INTERVAL = 2  # seconds
#     UTILIZATION_THRESHOLD = 500000  # bytes, threshold to trigger adaptive path selection

#     def __init__(self, *args, **kwargs):
#         super(DynamicECMP, self).__init__(*args, **kwargs)
#         self.graph = nx.DiGraph()
#         self.datapaths = {}
#         self.mac_to_port = {}
#         self.port_stats = {}
#         self.monitor_thread = hub.spawn(self._monitor)

#     @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
#     def switch_features_handler(self, ev):
#         datapath = ev.msg.datapath
#         self.datapaths[datapath.id] = datapath
#         parser = datapath.ofproto_parser
#         ofproto = datapath.ofproto

#         match = parser.OFPMatch()
#         actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
#         inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
#         mod = parser.OFPFlowMod(datapath=datapath, priority=0,
#                                 match=match, instructions=inst)
#         datapath.send_msg(mod)
#         self.logger.info("[BOOT] FLOOD rule installed on switch %s", datapath.id)

#     @set_ev_cls(event.EventSwitchEnter)
#     def get_topology(self, ev):
#         switch_list = get_switch(self, None)
#         switches = [sw.dp.id for sw in switch_list]
#         self.graph.add_nodes_from(switches)

#         link_list = get_link(self, None)
#         for link in link_list:
#             src = link.src.dpid
#             dst = link.dst.dpid
#             port = link.src.port_no
#             self.graph.add_edge(src, dst, port=port, weight=1)

#         self.logger.info("[TOPO] Switches: %s", switches)

#     def _monitor(self):
#         while True:
#             for dp in self.datapaths.values():
#                 self._request_stats(dp)
#             hub.sleep(self.STATS_INTERVAL)

#     def _request_stats(self, datapath):
#         parser = datapath.ofproto_parser
#         req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
#         datapath.send_msg(req)

#     @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
#     def _port_stats_reply_handler(self, ev):
#         dpid = ev.msg.datapath.id
#         self.port_stats[dpid] = {stat.port_no: stat.tx_bytes for stat in ev.msg.body}

#     def _get_best_path(self, src, dst):
#         try:
#             paths = list(nx.all_shortest_paths(self.graph, src, dst))
#         except nx.NetworkXNoPath:
#             return []

#         if not paths:
#             return []

#         # Check total load for each path
#         path_loads = []
#         for path in paths:
#             total_load = sum(self.port_stats.get(path[i], {}).get(
#                 self.graph[path[i]][path[i + 1]]['port'], 0)
#                 for i in range(len(path) - 1))
#             path_loads.append((total_load, path))

#         # Choose adaptive if all paths are above threshold
#         if all(load > self.UTILIZATION_THRESHOLD for load, _ in path_loads):
#             selected_path = min(path_loads, key=lambda x: x[0])[1]  # least loaded
#             self.logger.info("[PATH] Adaptive selected: %s", selected_path)
#         else:
#             selected_path = random.choice(paths)
#             self.logger.info("[PATH] Traditional selected: %s", selected_path)

#         return selected_path

#     @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
#     def packet_in_handler(self, ev):
#         msg = ev.msg
#         datapath = msg.datapath
#         parser = datapath.ofproto_parser
#         ofproto = datapath.ofproto
#         dpid = datapath.id
#         in_port = msg.match['in_port']

#         pkt = packet.Packet(msg.data)
#         eth = pkt.get_protocol(ethernet.ethernet)
#         ip_pkt = pkt.get_protocol(ipv4.ipv4)
#         if not ip_pkt:
#             return

#         dst_mac = eth.dst
#         src_mac = eth.src

#         self.mac_to_port.setdefault(dpid, {})
#         self.mac_to_port[dpid][src_mac] = in_port

#         dst_dpid = None
#         for sw_id, mac_table in self.mac_to_port.items():
#             if dst_mac in mac_table:
#                 dst_dpid = sw_id
#                 break

#         if dst_dpid is None:
#             actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
#             out = parser.OFPPacketOut(datapath=datapath,
#                                       buffer_id=msg.buffer_id,
#                                       in_port=in_port,
#                                       actions=actions,
#                                       data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
#             datapath.send_msg(out)
#             self.logger.info("[FLOOD] Unknown destination MAC, flooding")
#             return

#         path = self._get_best_path(dpid, dst_dpid)
#         if not path or len(path) < 2:
#             self.logger.warning("[PATH] Invalid path from %s to %s", dpid, dst_dpid)
#             return

#         for i in range(len(path) - 1):
#             curr_sw = path[i]
#             next_sw = path[i + 1]
#             out_port = self.graph[curr_sw][next_sw]['port']
#             dp = self.datapaths[curr_sw]
#             match = dp.ofproto_parser.OFPMatch(eth_dst=dst_mac)
#             actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
#             inst = [dp.ofproto_parser.OFPInstructionActions(
#                 dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
#             mod = dp.ofproto_parser.OFPFlowMod(datapath=dp, priority=10,
#                                                match=match, instructions=inst)
#             dp.send_msg(mod)
#             self.logger.info("[FLOW] Installed on sw=%s for dst_mac=%s -> port %s", curr_sw, dst_mac, out_port)

#         out_port = self.graph[dpid][path[1]]['port']
#         actions = [parser.OFPActionOutput(out_port)]
#         out = parser.OFPPacketOut(datapath=datapath,
#                                   buffer_id=msg.buffer_id,
#                                   in_port=in_port,
#                                   actions=actions,
#                                   data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
#         datapath.send_msg(out)
#         self.logger.info("[FORWARD] Packet forwarded from %s to %s via port %s", src_mac, dst_mac, out_port)


# from ryu.base import app_manager
# from ryu.controller import ofp_event
# from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
# from ryu.controller.handler import set_ev_cls
# from ryu.ofproto import ofproto_v1_3
# from ryu.topology import event
# from ryu.topology.api import get_switch, get_link
# from ryu.lib.packet import packet, ethernet, ipv4
# from ryu.lib import hub
# import networkx as nx
# import random

# class DynamicECMP(app_manager.RyuApp):
#     OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
#     STATS_INTERVAL = 2  # seconds
#     UTILIZATION_THRESHOLD = 50  # bytes, threshold to trigger adaptive path selection

#     def __init__(self, *args, **kwargs):
#         super(DynamicECMP, self).__init__(*args, **kwargs)
#         self.graph = nx.DiGraph()
#         self.datapaths = {}
#         self.mac_to_port = {}
#         self.port_stats = {}
#         self.monitor_thread = hub.spawn(self._monitor)

#     @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
#     def switch_features_handler(self, ev):
#         datapath = ev.msg.datapath
#         self.datapaths[datapath.id] = datapath
#         parser = datapath.ofproto_parser
#         ofproto = datapath.ofproto

#         match = parser.OFPMatch()
#         actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
#         inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
#         mod = parser.OFPFlowMod(datapath=datapath, priority=0,
#                                 match=match, instructions=inst)
#         datapath.send_msg(mod)
#         self.logger.info("[BOOT] FLOOD rule installed on switch %s", datapath.id)

#     @set_ev_cls(event.EventSwitchEnter)
#     def get_topology(self, ev):
#         switch_list = get_switch(self, None)
#         switches = [sw.dp.id for sw in switch_list]
#         self.graph.add_nodes_from(switches)

#         link_list = get_link(self, None)
#         for link in link_list:
#             src = link.src.dpid
#             dst = link.dst.dpid
#             port = link.src.port_no
#             self.graph.add_edge(src, dst, port=port, weight=1)

#         self.logger.info("[TOPO] Switches: %s", switches)

#     def _monitor(self):
#         while True:
#             for dp in self.datapaths.values():
#                 self._request_stats(dp)
#             hub.sleep(self.STATS_INTERVAL)

#     def _request_stats(self, datapath):
#         parser = datapath.ofproto_parser
#         req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
#         datapath.send_msg(req)

#     @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
#     def _port_stats_reply_handler(self, ev):
#         dpid = ev.msg.datapath.id
#         self.port_stats[dpid] = {stat.port_no: stat.tx_bytes for stat in ev.msg.body}

#     def _get_best_path(self, src, dst):
#         try:
#             paths = list(nx.all_shortest_paths(self.graph, src, dst))
#         except nx.NetworkXNoPath:
#             return []

#         if not paths:
#             return []

#         # Check total load for each path
#         path_loads = []
#         for path in paths:
#             total_load = sum(self.port_stats.get(path[i], {}).get(
#                 self.graph[path[i]][path[i + 1]]['port'], 0)
#                 for i in range(len(path) - 1))
#             path_loads.append((total_load, path))

#         # Choose adaptive if all paths are above threshold
#         if all(load > self.UTILIZATION_THRESHOLD for load, _ in path_loads):
#             selected_path = min(path_loads, key=lambda x: x[0])[1]  # least loaded
#             self.logger.info("[PATH] Adaptive ECMP selected: %s", selected_path)
#             print("[ECMP_MODE] Using Adaptive ECMP")
#         else:
#             selected_path = random.choice(paths)
#             self.logger.info("[PATH] Traditional ECMP selected: %s", selected_path)
#             print("[ECMP_MODE] Using Traditional ECMP")

#         return selected_path

#     @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
#     def packet_in_handler(self, ev):
#         msg = ev.msg
#         datapath = msg.datapath
#         parser = datapath.ofproto_parser
#         ofproto = datapath.ofproto
#         dpid = datapath.id
#         in_port = msg.match['in_port']

#         pkt = packet.Packet(msg.data)
#         eth = pkt.get_protocol(ethernet.ethernet)
#         ip_pkt = pkt.get_protocol(ipv4.ipv4)
#         if not ip_pkt:
#             return

#         dst_mac = eth.dst
#         src_mac = eth.src

#         self.mac_to_port.setdefault(dpid, {})
#         self.mac_to_port[dpid][src_mac] = in_port

#         dst_dpid = None
#         for sw_id, mac_table in self.mac_to_port.items():
#             if dst_mac in mac_table:
#                 dst_dpid = sw_id
#                 break

#         if dst_dpid is None:
#             actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
#             out = parser.OFPPacketOut(datapath=datapath,
#                                       buffer_id=msg.buffer_id,
#                                       in_port=in_port,
#                                       actions=actions,
#                                       data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
#             datapath.send_msg(out)
#             self.logger.info("[FLOOD] Unknown destination MAC, flooding")
#             return

#         path = self._get_best_path(dpid, dst_dpid)
#         if not path or len(path) < 2:
#             self.logger.warning("[PATH] Invalid path from %s to %s", dpid, dst_dpid)
#             return

#         for i in range(len(path) - 1):
#             curr_sw = path[i]
#             next_sw = path[i + 1]
#             out_port = self.graph[curr_sw][next_sw]['port']
#             dp = self.datapaths[curr_sw]
#             match = dp.ofproto_parser.OFPMatch(eth_dst=dst_mac)
#             actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
#             inst = [dp.ofproto_parser.OFPInstructionActions(
#                 dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
#             mod = dp.ofproto_parser.OFPFlowMod(datapath=dp, priority=10,
#                                                match=match, instructions=inst)
#             dp.send_msg(mod)
#             self.logger.info("[FLOW] Installed on sw=%s for dst_mac=%s -> port %s", curr_sw, dst_mac, out_port)

#         out_port = self.graph[dpid][path[1]]['port']
#         actions = [parser.OFPActionOutput(out_port)]
#         out = parser.OFPPacketOut(datapath=datapath,
#                                   buffer_id=msg.buffer_id,
#                                   in_port=in_port,
#                                   actions=actions,
#                                   data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
#         datapath.send_msg(out)
#         self.logger.info("[FORWARD] Packet forwarded from %s to %s via port %s", src_mac, dst_mac, out_port)

# from ryu.base import app_manager
# from ryu.controller import ofp_event
# from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
# from ryu.controller.handler import set_ev_cls
# from ryu.ofproto import ofproto_v1_3
# from ryu.topology import event
# from ryu.topology.api import get_switch, get_link
# from ryu.lib.packet import packet, ethernet, ipv4,arp
# from ryu.lib import hub 
# import networkx as nx
# import random

# class DynamicECMP(app_manager.RyuApp):
#     OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
#     STATS_INTERVAL = 2  # seconds
#     UTILIZATION_THRESHOLD = 50  # bytes, threshold to trigger adaptive path selection

#     def __init__(self, *args, **kwargs):
#         super(DynamicECMP, self).__init__(*args, **kwargs)
#         self.graph = nx.DiGraph()
#         self.datapaths = {}
#         self.mac_to_port = {}
#         self.port_stats = {}
#         self.monitor_thread = hub.spawn(self._monitor)

#     @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
#     def switch_features_handler(self, ev):
#         datapath = ev.msg.datapath
#         self.datapaths[datapath.id] = datapath
#         parser = datapath.ofproto_parser
#         ofproto = datapath.ofproto

#         match = parser.OFPMatch()
#         actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
#         inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
#         mod = parser.OFPFlowMod(datapath=datapath, priority=0,
#                                 match=match, instructions=inst)
#         datapath.send_msg(mod)
#         self.logger.info("[BOOT] FLOOD rule installed on switch %s", datapath.id)

#     @set_ev_cls(event.EventSwitchEnter)
#     def get_topology(self, ev):
#         switch_list = get_switch(self, None)
#         switches = [sw.dp.id for sw in switch_list]
#         self.graph.add_nodes_from(switches)

#         link_list = get_link(self, None)
#         for link in link_list:
#             src = link.src.dpid
#             dst = link.dst.dpid
#             port = link.src.port_no
#             self.graph.add_edge(src, dst, port=port, weight=1)

#         self.logger.info("[TOPO] Switches: %s", switches)

#     def _monitor(self):
#         while True:
#             for dp in self.datapaths.values():
#                 self._request_stats(dp)
#             hub.sleep(self.STATS_INTERVAL)

#     def _request_stats(self, datapath):
#         parser = datapath.ofproto_parser
#         req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
#         datapath.send_msg(req)

#     @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
#     def _port_stats_reply_handler(self, ev):
#         dpid = ev.msg.datapath.id
#         self.port_stats[dpid] = {stat.port_no: stat.tx_bytes for stat in ev.msg.body}

#     def _get_best_path(self, src, dst):
#         try:
#             paths = list(nx.all_shortest_paths(self.graph, src, dst))
#         except nx.NetworkXNoPath:
#             return []

#         if not paths:
#             return []

#         # Check total load for each path
#         path_loads = []
#         for path in paths:
#             total_load = sum(self.port_stats.get(path[i], {}).get(
#                 self.graph[path[i]][path[i + 1]]['port'], 0)
#                 for i in range(len(path) - 1))
#             path_loads.append((total_load, path))

#         # Choose adaptive if all paths are above threshold
#         if all(load > self.UTILIZATION_THRESHOLD for load, _ in path_loads):
#             selected_path = min(path_loads, key=lambda x: x[0])[1]  # least loaded
#             self.logger.info("[PATH] Adaptive ECMP selected: %s", selected_path)
#             print("[ECMP_MODE] Using Adaptive ECMP")
#         else:
#             selected_path = random.choice(paths)
#             self.logger.info("[PATH] Traditional ECMP selected: %s", selected_path)
#             print("[ECMP_MODE] Using Traditional ECMP")

#         return selected_path

#     @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
#     def packet_in_handler(self, ev):
#         msg = ev.msg
#         datapath = msg.datapath
#         parser = datapath.ofproto_parser
#         ofproto = datapath.ofproto
#         dpid = datapath.id
#         in_port = msg.match['in_port']

#         pkt = packet.Packet(msg.data)
#         eth = pkt.get_protocol(ethernet.ethernet)
#         ip_pkt = pkt.get_protocol(ipv4.ipv4)
#         if not ip_pkt:
#             return

#         dst_mac = eth.dst
#         src_mac = eth.src

#         self.mac_to_port.setdefault(dpid, {})
#         self.mac_to_port[dpid][src_mac] = in_port

#         dst_dpid = None
#         for sw_id, mac_table in self.mac_to_port.items():
#             if dst_mac in mac_table:
#                 dst_dpid = sw_id
#                 break

#         if dst_dpid is None:
#             actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
#             out = parser.OFPPacketOut(datapath=datapath,
#                                       buffer_id=msg.buffer_id,
#                                       in_port=in_port,
#                                       actions=actions,
#                                       data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
#             datapath.send_msg(out)
#             self.logger.info("[FLOOD] Unknown destination MAC, flooding")
#             return

#         path = self._get_best_path(dpid, dst_dpid)
#         if not path or len(path) < 2:
#             self.logger.warning("[PATH] Invalid path from %s to %s", dpid, dst_dpid)
#             return

#         for i in range(len(path) - 1):
#             curr_sw = path[i]
#             next_sw = path[i + 1]
#             out_port = self.graph[curr_sw][next_sw]['port']
#             dp = self.datapaths[curr_sw]
#             match = dp.ofproto_parser.OFPMatch(eth_dst=dst_mac)
#             actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
#             inst = [dp.ofproto_parser.OFPInstructionActions(
#                 dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
#             mod = dp.ofproto_parser.OFPFlowMod(datapath=dp, priority=10,
#                                                match=match, instructions=inst)
#             dp.send_msg(mod)
#             self.logger.info("[FLOW] Installed on sw=%s for dst_mac=%s -> port %s", curr_sw, dst_mac, out_port)

#         out_port = self.graph[dpid][path[1]]['port']
#         actions = [parser.OFPActionOutput(out_port)]
#         out = parser.OFPPacketOut(datapath=datapath,
#                                   buffer_id=msg.buffer_id,
#                                   in_port=in_port,
#                                   actions=actions,
#                                   data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
#         datapath.send_msg(out)
#         self.logger.info("[FORWARD] Packet forwarded from %s to %s via port %s", src_mac, dst_mac, out_port)



from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib import hub
import networkx as nx
import random


class DynamicECMP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    STATS_INTERVAL = 2  # seconds
    UTILIZATION_THRESHOLD = 50  # bytes

    def __init__(self, *args, **kwargs):
        super(DynamicECMP, self).__init__(*args, **kwargs)
        self.graph = nx.DiGraph()
        self.datapaths = {}
        self.mac_to_port = {}
        self.port_stats = {}
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Default flow: flood unknown traffic
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info("[BOOT] Flood rule installed on switch %s", datapath.id)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology(self, ev):
        switch_list = get_switch(self, None)
        switches = [sw.dp.id for sw in switch_list]
        self.graph.add_nodes_from(switches)

        link_list = get_link(self, None)
        for link in link_list:
            src = link.src.dpid
            dst = link.dst.dpid
            port = link.src.port_no
            self.graph.add_edge(src, dst, port=port, weight=1)

        self.logger.info("[TOPO] Switches: %s", switches)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.STATS_INTERVAL)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        self.port_stats[dpid] = {stat.port_no: stat.tx_bytes for stat in ev.msg.body}

    def _get_best_path(self, src, dst):
        try:
            paths = list(nx.all_shortest_paths(self.graph, src, dst))
        except nx.NetworkXNoPath:
            return []

        if not paths:
            return []

        path_loads = []
        for path in paths:
            total_load = sum(self.port_stats.get(path[i], {}).get(
                self.graph[path[i]][path[i + 1]]['port'], 0)
                for i in range(len(path) - 1))
            path_loads.append((total_load, path))

        if all(load > self.UTILIZATION_THRESHOLD for load, _ in path_loads):
            selected_path = min(path_loads, key=lambda x: x[0])[1]
            self.logger.info("[PATH] Adaptive ECMP selected: %s", selected_path)
            print("[ECMP_MODE] Using Adaptive ECMP")
        else:
            selected_path = random.choice(paths)
            self.logger.info("[PATH] Traditional ECMP selected: %s", selected_path)
            print("[ECMP_MODE] Using Traditional ECMP")

        return selected_path

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        dst_mac = eth.dst
        src_mac = eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        self.logger.info("[PKTIN] sw=%s in_port=%s src=%s dst=%s", dpid, in_port, src_mac, dst_mac)

        # Handle ARP packets
        if arp_pkt:
            self.logger.info("[ARP] Handling ARP packet %s -> %s", arp_pkt.src_ip, arp_pkt.dst_ip)
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)
            return

        if not ip_pkt:
            return  # Ignore non-IP packets (e.g., LLDP)

        # Find destination switch
        dst_dpid = None
        for sw_id, mac_table in self.mac_to_port.items():
            if dst_mac in mac_table:
                dst_dpid = sw_id
                break

        if dst_dpid is None:
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
            datapath.send_msg(out)
            self.logger.info("[FLOOD] Unknown dst MAC, flooding")
            return

        path = self._get_best_path(dpid, dst_dpid)
        if not path or len(path) < 2:
            self.logger.warning("[PATH] Invalid path from %s to %s", dpid, dst_dpid)
            return

        # Install flow on each switch in path
        for i in range(len(path) - 1):
            curr_sw = path[i]
            next_sw = path[i + 1]
            out_port = self.graph[curr_sw][next_sw]['port']
            dp = self.datapaths[curr_sw]
            match = dp.ofproto_parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
            actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
            inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = dp.ofproto_parser.OFPFlowMod(
                datapath=dp,
                priority=10,
                match=match,
                instructions=inst,
                idle_timeout=10,
                hard_timeout=30
            )
            dp.send_msg(mod)
            self.logger.info("[FLOW] Installed on sw=%s: %s → %s via port %s",
                             curr_sw, src_mac, dst_mac, out_port)

        # Forward the current packet along the first hop
        out_port = self.graph[dpid][path[1]]['port']
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)
        self.logger.info("[FORWARD] Packet forwarded from %s to %s via port %s", src_mac, dst_mac, out_port)
