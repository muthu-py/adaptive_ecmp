
from operator import attrgetter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp,arp
from ryu.lib import hub


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.logger.info('SimpleSwitch13 initialized')
        self.mac_to_port = {}
        self.group_mod_flag = {}

        # monitor
        self.sleep = 2
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.tx_pkt_cur = {}    # currently monitoring TX packets
        self.tx_byte_cur = {}   # currently monitoring TX bytes
        self.tx_pkt_int = {}    # TX packets in the last monitoring interval
        self.tx_byte_int = {}    # TX bytes in the last monitoring interval

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info('new switch connected %s',dpid)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, match, actions)

        # Only set up group table on leaves (201, 202)
        if dpid in [201, 202]:
            self.group_mod_flag[dpid] = True
            if self.group_mod_flag[dpid] is True:
                self.send_group_mod(datapath)
                self.logger.info("send_group_mod")
                self.group_mod_flag[dpid] = False

    def add_flow(self, datapath, hard_timeout, priority, match, actions, buffer_id=None):
    # def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority,
                                    hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
            
        
        datapath.send_msg(mod)

    def send_group_mod(self, datapath, port_weights=None):
            ofproto = datapath.ofproto
            ofp_parser = datapath.ofproto_parser

            # Default ports
            port_1 = 1
            port_2 = 2
            queue_1 = ofp_parser.OFPActionSetQueue(0)
            actions_1 = [queue_1, ofp_parser.OFPActionOutput(port_1)]
            queue_2 = ofp_parser.OFPActionSetQueue(0)
            actions_2 = [queue_2, ofp_parser.OFPActionOutput(port_2)]
            # Default weights
            weight_1 = 50
            weight_2 = 50
            if port_weights:
                weight_1 = port_weights.get(port_1, 1)
                weight_2 = port_weights.get(port_2, 1)
            watch_port = ofproto_v1_3.OFPP_ANY
            watch_group = ofproto_v1_3.OFPQ_ALL
            buckets = [
                ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
                ofp_parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]
            group_id = 50
            # Use MODIFY if group already exists, else ADD
            if hasattr(ofproto, 'OFPFC_MODIFY'):  # Defensive
                command = ofproto.OFPFC_MODIFY
            else:
                command = ofproto.OFPFC_ADD
            req = ofp_parser.OFPGroupMod(datapath, command,
                                        ofproto.OFPGT_SELECT, group_id, buckets)

            datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Only log packet-in at debug level, and only once per unique src/dst/in_port if needed
        # self.logger.debug('Packet-in event received')
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
            
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            # Only log ARP at debug level, and only once per unique src/dst if needed
            # self.logger.debug("Received ARP: %s -> %s", arp_pkt.src_ip, arp_pkt.dst_ip)
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
            return

        if eth.dst.startswith('33:33'):
            # Ignore IPv6 multicast packets
            return
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Determine host-facing ports for this topology
        # For leaves (201, 202): ports 3 and 4 are host-facing
        # For spines (101, 102): no host-facing ports, always use group
        host_ports = [3, 4] if str(dpid).startswith('2') else []

        out_port = None
        actions = None
        if dpid in [201, 202]:  # Leaf
            if in_port in [3, 4]:  # From host
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                    if out_port in [3, 4]:
                        # Intra-leaf: direct output
                        actions = [parser.OFPActionOutput(out_port)]
                    else:
                        # Inter-leaf: group action (uplink)
                        actions = [parser.OFPActionGroup(group_id=50)]
                else:
                    # Unknown: flood to other host port and group
                    actions = [parser.OFPActionOutput(4 if in_port == 3 else 3),
                               parser.OFPActionGroup(group_id=50)]
            elif in_port in [1, 2]:  # From spine
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                    actions = [parser.OFPActionOutput(out_port)]
                else:
                    actions = [parser.OFPActionOutput(3), parser.OFPActionOutput(4)]
            else:
                # Unknown port
                pass
        elif dpid in [101, 102]:  # Spine
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
                actions = [parser.OFPActionOutput(out_port)]
            else:
                actions = [ofproto.OFPP_FLOOD]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        self.logger.info('''
                         
                         
                         [FORWARD] Sent packet from %s to %s via group 50 dpid %s
                         
                         
                         
                         
                         ''', src, dst, dpid)

# ==================================================
#                   Monitor
# ==================================================

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.sleep)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # req = parser.OFPFlowStatsRequest(datapath)
        # datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id

        if dpid == 513 or dpid == 514:
            body = ev.msg.body

            self.logger.info('datapath         '
                             'in-port  eth-dst           '
                             'out-port packets  bytes')
            self.logger.info('---------------- '
                             '-------- ----------------- '
                             '-------- -------- --------')
            for stat in sorted([flow for flow in body if flow.priority == 1],
                               key=lambda flow: (flow.match['in_port'],
                                                 flow.match['eth_dst'])):
                self.logger.info('%016x %8x %17s %8x %8d %8d',
                                 ev.msg.datapath.id,
                                 stat.match['in_port'], stat.match['eth_dst'],
                                 stat.instructions[0].actions[0].port,
                                 stat.packet_count, stat.byte_count)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        body = ev.msg.body
        if dpid == 201:
            self.logger.info('datapath         port     tx-pkts  tx-bytes')
            self.logger.info('---------------- -------- -------- --------')
        max_bw = 1  # Avoid division by zero
        port_bw = {}
        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            self.tx_pkt_cur.setdefault(dpid, {})
            self.tx_byte_cur.setdefault(dpid, {})
            self.tx_pkt_int.setdefault(dpid, {})
            self.tx_byte_int.setdefault(dpid, {})
            if port_no in self.tx_pkt_cur[dpid]:
                self.tx_pkt_int[dpid][port_no] = stat.tx_packets - self.tx_pkt_cur[dpid][port_no]
                if self.tx_pkt_int[dpid][port_no] < 0:
                    self.logger.warning('Negative value of interval TX packets')
            self.tx_pkt_cur[dpid][port_no] = stat.tx_packets
            if port_no in self.tx_byte_cur[dpid]:
                self.tx_byte_int[dpid][port_no] = stat.tx_bytes - self.tx_byte_cur[dpid][port_no]
                if self.tx_byte_int[dpid][port_no] < 0:
                    self.logger.warning('Negative value of interval TX bytes')
            self.tx_byte_cur[dpid][port_no] = stat.tx_bytes
            # Calculate available bandwidth as inverse of tx_bytes in interval
            bw = max(1, 1000000 - self.tx_byte_int[dpid].get(port_no, 0))
            port_bw[port_no] = bw
            if bw > max_bw:
                max_bw = bw
            if dpid == 201:
                if port_no in self.tx_pkt_int[dpid] and port_no in self.tx_byte_int[dpid]:
                    self.logger.info('%016x %8x %8d %8d', dpid, port_no,
                                    self.tx_pkt_int[dpid][port_no],
                                    self.tx_byte_int[dpid][port_no])
        # Only update group table on leaves
        if dpid in [201, 202]:
            total_bw = sum(port_bw.values())
            if total_bw > 0:
                port_weights = {p: int((bw / total_bw) * 100) for p, bw in port_bw.items()}
            else:
                port_weights = {p: 50 for p in port_bw}  # fallback
            datapath = ev.msg.datapath
            self.send_group_mod(datapath, port_weights=port_weights)