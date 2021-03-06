# Copyright (C) 2016 Li Cheng at Beijing University of Posts
# and Telecommunications. www.muzixing.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# conding=utf-8
import logging
import struct
import networkx as nx
from operator import attrgetter
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import lldp
from ryu.lib.packet import ether_types

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

import network_awareness
import network_monitor
import network_delay_detector


CONF = cfg.CONF


class ShortestForwarding(app_manager.RyuApp):
    """
        ShortestForwarding is a Ryu app for forwarding packets in shortest
        path.
        The shortest path computation is done by module network awareness,
        network monitor and network delay detector.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "network_awareness": network_awareness.NetworkAwareness,
        "network_monitor": network_monitor.NetworkMonitor,
        "network_delay_detector": network_delay_detector.NetworkDelayDetector}

    WEIGHT_MODEL = {'hop': 'weight', 'delay': "delay", "bw": "bw"}

    def __init__(self, *args, **kwargs):
        super(ShortestForwarding, self).__init__(*args, **kwargs)
        self.name = 'shortest_forwarding'
        self.awareness = kwargs["network_awareness"]
        self.monitor = kwargs["network_monitor"]
        self.delay_detector = kwargs["network_delay_detector"]
        self.datapaths = {}
        self.weight = self.WEIGHT_MODEL[CONF.weight]
        self.gid = 0

    def set_weight_mode(self, weight):
        """
            set weight mode of path calculating.
        """
        self.weight = weight
        if self.weight == self.WEIGHT_MODEL['hop']:
            self.awareness.get_shortest_paths(weight=self.weight)
        return True

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
            Collect datapath information.
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        """
            Send a flow entry to datapath.
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    def send_flow_mod(self, datapath, flow_info, src_port, dst_port, group_id=0):
        """
            Build flow entry, and send it to datapath.
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = []
        if group_id == 0:
            actions.append(parser.OFPActionOutput(dst_port))
        else:
            actions.append(parser.OFPActionGroup(group_id))
        if src_port == 0:
            match = parser.OFPMatch(
                eth_type=flow_info[0],
                ipv4_src=flow_info[1], ipv4_dst=flow_info[2])

            self.add_flow(datapath, 1, match, actions,
                          idle_timeout=0, hard_timeout=0)
        else:
            match = parser.OFPMatch(
                in_port=src_port, eth_type=flow_info[0],
                ipv4_src=flow_info[1], ipv4_dst=flow_info[2])

            self.add_flow(datapath, 1, match, actions,
                          idle_timeout=0, hard_timeout=0)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Build packet out object.
        """
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        """
            Send packet out packet to assigned datapath.
        """
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def get_port(self, dst_ip, access_table):
        """
            Get access port if dst host.
            access_table: {(sw,port) :(ip, mac)}
        """
        k = []
        v = []
        if access_table:
            k = list(access_table.keys())
            v = list(access_table.values())             
            if isinstance(v[0], tuple):
                for key in k:
                    if dst_ip == access_table[key][0]:
                        dst_port = key[1]
                        return dst_port
        return None

    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        """
            Get port pair of link, so that controller can install flow entry.
        """
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("dpid:%s->dpid:%s is not in links" % (
                             src_dpid, dst_dpid))
            return None

    def flood(self, msg):
        """
            Flood ARP packet to the access port
            which has no record of host.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.awareness.access_ports:
            for port in self.awareness.access_ports[dpid]:
                if (dpid, port) not in self.awareness.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)
        self.logger.debug("Flooding msg")

    def arp_forwarding(self, msg, src_ip, dst_ip):
        """ Send ARP packet to the destination host,
            if the dst host record is existed,
            else, flow it to the unknow access port.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        result = self.awareness.get_host_location(dst_ip)
        if result:  # host record in access table.
            datapath_dst, out_port = result[0], result[1]
            datapath = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath.send_msg(out)
            self.logger.debug("Reply ARP to knew host")
        else:
            self.flood(msg)

    def get_path(self, src, dst, weight):
        """
            Get shortest path from network awareness module.
        """
        shortest_paths = self.awareness.shortest_paths
        graph = self.awareness.graph

        if weight == self.WEIGHT_MODEL['hop']:
            paths = shortest_paths.get(src).get(dst)
            #print('get_path:', src, dst, paths)
            return paths
        elif weight == self.WEIGHT_MODEL['delay']:
            # If paths existed, return it, else calculate it and save it.
            try:
                paths = shortest_paths.get(src).get(dst)
                return paths[0]
            except:
                paths = self.awareness.k_shortest_paths(graph, src, dst,
                                                        weight=weight)

                shortest_paths.setdefault(src, {})
                shortest_paths[src].setdefault(dst, paths)
                return paths[0]
        elif weight == self.WEIGHT_MODEL['bw']:
            # Because all paths will be calculate
            # when call self.monitor.get_best_path_by_bw
            # So we just need to call it once in a period,
            # and then, we can get path directly.
            try:
                # if path is existed, return it.
                path = self.monitor.best_paths.get(src).get(dst)
                return path
            except:
                # else, calculate it, and return.
                result = self.monitor.get_best_path_by_bw(graph,
                                                          shortest_paths)
                paths = result[1]
                best_path = paths.get(src).get(dst)
                return best_path

    def get_sw(self, dpid, in_port, src, dst):
        """
            Get pair of source and destination switches.
        """
        src_sw = dpid
        dst_sw = None

        src_location = self.awareness.get_host_location(src)
        if in_port in self.awareness.access_ports[dpid]:
            if (dpid,  in_port) == src_location:
                src_sw = src_location[0]
            else:
                return None

        dst_location = self.awareness.get_host_location(dst)
        if dst_location:
            dst_sw = dst_location[0]

        return src_sw, dst_sw

    def send_group_mod(self, datapath, group_id_1, out_port_1, out_port_2, watch_port_2=0):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        actions_1 = [ofp_parser.OFPActionOutput(out_port_1)]
        watch_port_1 = out_port_1
        actions_2 = [ofp_parser.OFPActionOutput(out_port_2)]
        if watch_port_2 == 0:
            watch_port_2 = out_port_2
        else:
            watch_port_2 = watch_port_2
 
        buckets = [ofp_parser.OFPBucket(watch_port=watch_port_1, watch_group=0,
                                        actions=actions_1), 
                   ofp_parser.OFPBucket(watch_port=watch_port_2, watch_group=0,
                                        actions=actions_2)]

        group_id = group_id_1
        req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                     ofp.OFPGT_FF, group_id, buckets)
        datapath.send_msg(req)


    def install_flow(self, datapaths, link_to_port, cir_list, access_table,
                     paths, flow_info, buffer_id, data=None):
        ''' 
            Install flow entires for roundtrip: go and back.
            @parameter: path=[dpid1, dpid2...]
                        flow_info=(eth_type, src_ip, dst_ip, in_port)
        '''
        if len(paths) > 1:
            path, path_ = paths[0], paths[1]
        else:
            path = paths[0]
        #------ working path install
        if path is None or len(path) == 0:
            self.logger.info("Path error!")
            return
        in_port = flow_info[3]
        first_dp = datapaths[path[0]]
        out_port = first_dp.ofproto.OFPP_LOCAL
        back_info = (flow_info[0], flow_info[2], flow_info[1])

        ###~~~~new~~~~~
        b = 0
        len_cir = len(cir_list)
        len_pa = len(path)
        path_cir = []
        bp_cir = []
        cir_cnt = 0
        cir_dir = []   # -1 means anticlockwise
        bp_exclue = []

        if len(path) <2:
            return
        print('cir_list:', cir_list)
        ##------first_dp-----------
        port_pair = self.get_port_pair_from_link(link_to_port,
					         path[0], path[1])
        out_port = port_pair[0]
                # backward_wildcard
        self.send_flow_mod(first_dp, back_info, 0, in_port)
        for j in range(len_cir):
            if path[0] in cir_list[j] and path[1] in cir_list[j]:
                print('first_cir:', cir_list[j])
                bp_cir = cir_list[j]
                p = bp_cir.index(path[0])
                try:
                    if path[1] == bp_cir[p+1]:
                        bp = bp_cir[p-1]
                        cir_dir.append(-1)
                    else:
                        bp = bp_cir[p+1]
                        cir_dir.append(1)
                except IndexError:
                    if path[1] == bp_cir[0]:
                        bp = bp_cir[p-1]
                        cir_dir.append(-1)
                    else:
                        bp = bp_cir[0]
                        cir_dir.append(1)
                port_pair = self.get_port_pair_from_link(link_to_port,
                                                         path[0], bp)
                bp_port = port_pair[0]
                # forward_ffg
                self.send_group_mod(first_dp, self.gid, out_port, bp_port)
                self.send_flow_mod(first_dp, flow_info, in_port, out_port, self.gid)
                # match return packets
                self.send_flow_mod(first_dp, flow_info, out_port, bp_port)
                path_cir.append(bp_cir)
                #bp_exclue[0].append(path[0])
                #bp_exclue[0].append(path[1])
                cir_cnt = 1
                b = 1
                break
            # forward_no_bp 
        if b == 0:
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
        b = 0
           
        ##------last_dp-----------
        last_dp = datapaths[path[-1]]
        port_pair = self.get_port_pair_from_link(link_to_port,
                                             path[-2], path[-1])
        src_port = port_pair[1]
        dst_port = self.get_port(flow_info[2], access_table)
                # forkward_wildcard
        self.send_flow_mod(last_dp, flow_info, 0, dst_port)
        for j in range(len_cir):
            if path[-2] in cir_list[j] and path[-1] in cir_list[j]:
                bp_cir = cir_list[j]
                print('last_cir:', bp_cir)
                p = bp_cir.index(path[-1])
                for k in range(len(path_cir)):
                    if path[-2] in path_cir[k] and path[-1] in path_cir[k]:
                        bp_cir = path_cir[k]
                        #bp_exclue[cir_cnt].append(path[-2])
                        #bp_exclue[cir_cnt].append(path[-1])
                        break
                    else:
                        if k == len(path_cir)-1:
                            path_cir.append(cir_list[j])
                            bp_cir = cir_list[j]
                            cir_cnt += 1
                            #bp_exclue[cir_cnt] = [path[-2], path[-1]]
                            if path[-2] == bp_cir[p-1]:
                                cir_dir.append(-1)
                            else:
                                cir_dir.append(1)
                        else:
                            continue
                try:
                    if path[-2] == bp_cir[p+1]:
                        bp = bp_cir[p-1]
                    else:
                        bp = bp_cir[p+1]
                except IndexError:
                    if path[-2] == bp_cir[0]:
                        bp = bp_cir[p-1]
                    else:
                        bp = bp_cir[0]
                port_pair = self.get_port_pair_from_link(link_to_port,
                                                         path[-1], bp)
                bp_port = port_pair[0]
                # backward_ffg
                self.send_group_mod(last_dp, self.gid, src_port, bp_port)
                self.send_flow_mod(last_dp, back_info, dst_port, src_port, self.gid)
                # match return packets
                self.send_flow_mod(last_dp, back_info, src_port, bp_port)
                b = 1
                break
            # backward_no_bp 
        if b == 0:
            self.send_flow_mod(last_dp, back_info, dst_port, src_port)
        b = 0

        ##-------inter_dp----------
        cir_01 = []
        ad = 0
        if len_pa > 2:
            for i in range(1, len_pa-1):
                datapath = datapaths[path[i]]
                print('~~~~  path[i]:', path[i])
                port_pair = self.get_port_pair_from_link(link_to_port,
                                                   path[i-1], path[i])
                port_next = self.get_port_pair_from_link(link_to_port,
                                                   path[i], path[i+1])
                src_port, dst_port = port_pair[1], port_next[0]
                for j in range(len_cir):
                        #p = cir_list[j].index(path[i])
                    if path[i-1] in cir_list[j] and path[i] in cir_list[j] and path[i+1] not in cir_list[j]:
                        p = cir_list[j].index(path[i])
                        f = 0
                        print('inter_circle_10:', cir_list[j])
                        try:
                            if path[i-1] == cir_list[j][p+1]:
                                bp = cir_list[j][p-1]
                            else:
                                bp = cir_list[j][p+1]
                        except IndexError:
                            if path[i-1] == cir_list[j][0]:
                                bp = cir_list[j][p-1]
                            else:
                                bp = cir_list[j][0]
                        bp_port = self.get_port_pair_from_link(link_to_port,
                                                                path[i], bp)[0]
                        for m in range(len_cir):
                            if path[i] in cir_list[m] and path[i+1] in cir_list[m]:
                                bp_cir_ = cir_list[m]
                                print ('bp_cir__101', bp_cir_)
                                p_ = bp_cir_.index(path[i])
                                if bp_cir_ in path_cir:
                                    pass
                                else:
                                    path_cir.append(bp_cir_)
                                    cir_cnt += 1
                                    try:
                                        if path[i+1] == bp_cir_[p_+1]:
                                            cir_dir.append(-1)
                                        else:
                                            cir_dir.append(1)
                                    except IndexError:
                                        if path[i+1] == bp_cir_[0]:
                                            cir_dir.append(-1)
                                        else:
                                            cir_dir.append(1)
                                if path[i-1] in bp_cir_:
                                    print('inter_circle_1011')
                                    f = 1
                                    # forward_wildcard_ffg
                                    self.send_group_mod(datapath, self.gid, dst_port,
                                                        datapath.ofproto.OFPP_IN_PORT, src_port)
                                    self.send_flow_mod(datapath, flow_info, bp_port, dst_port)
                                    self.send_flow_mod(datapath, flow_info, src_port, dst_port,
                                                       self.gid)
                                      # match return packets
                                    self.send_flow_mod(datapath, flow_info, dst_port, src_port)
                                    # backward_ffg
                                    self.send_group_mod(datapath, self.gid+1, src_port, bp_port)
                                    self.send_flow_mod(datapath, back_info, dst_port, src_port,
                                                       self.gid+1)
                                    datapath_ = datapaths[path[i-1]]
                                    p_ = bp_cir_.index(path[i-1])
                                    try:
                                        if path[i] == bp_cir_[p_+1]:
                                            bp_ = bp_cir_[p_-1]
                                        else:
                                            bp_ = bp_cir_[p_+1]
                                    except IndexError:
                                        if path[i+1] == bp_cir_[0]:
                                            bp_ = bp_cir_[p_-1]
                                        else:
                                            bp_ = bp_cir_[0]
                                    bp_port_ = self.get_port_pair_from_link(link_to_port,
                                                                            path[i-1], bp_)[0]
                                    self.send_flow_mod(datapath_, flow_info, port_pair[0], bp_port_)
                                    h = 0
                                    for n in range(i):
                                        datapath_ = datapaths[path[n]]
                                        if h == 1:
                                            src_port_ = self.get_port_pair_from_link(link_to_port,
                                                                                    path[n], path[n-1])[0]
                                            dst_port_ = self.get_port_pair_from_link(link_to_port,
                                                                                    path[n], path[n+1])[0]
                                            self.send_flow_mod(datapath_, flow_info, dst_port_, src_port_)
                                            continue
                                        if path[n] in bp_cir_:
                                            p_ = bp_cir_.index(path[n])
                                            try:
                                                if path[n+1] == bp_cir_[p_+1]:
                                                    bp_ = bp_cir_[p_-1]
                                                else:
                                                    bp_ = bp_cir_[p_+1]
                                            except IndexError:
                                                if path[n+1] == bp_cir_[0]:
                                                    bp_ = bp_cir_[p_-1]
                                                else:
                                                    bp_ = bp_cir_[0]
                                            bp_port_ = self.get_port_pair_from_link(link_to_port,
                                                                                    path[n], bp_)[0]
                                            dst_port_ = self.get_port_pair_from_link(link_to_port,
                                                                                    path[n], path[n+1])[0]
                                            self.send_flow_mod(datapath_, flow_info, dst_port_, bp_port_)
                                            h = 1
                                            continue
                                    break
                                else:
                                    print('inter_circle_1010')
                                    f = 1
                                    p_ = bp_cir_.index(path[i])
                                    try:
                                        if path[i+1] == bp_cir_[p_+1]:
                                            bp_ = bp_cir_[p_-1]
                                        else:
                                            bp_ = bp_cir_[p_+1]
                                    except IndexError:
                                        if path[i+1] == bp_cir_[0]:
                                            bp_ = bp_cir_[p_-1]
                                        else:
                                            bp_ = bp_cir_[0]
                                    bp_port_ = self.get_port_pair_from_link(link_to_port,
                                                                            path[i], bp_)[0]
                                    # forward_wildcard_ffg
                                    self.send_group_mod(datapath, self.gid, dst_port, bp_port_)
                                    self.send_flow_mod(datapath, flow_info, src_port, dst_port,
                                                       self.gid)
                                    self.send_flow_mod(datapath, flow_info, bp_port, dst_port,
                                                       self.gid)
                                    # match_fir_return
                                    self.send_flow_mod(datapath, back_info, src_port, bp_port)
                                    # match_sec_return
                                    self.send_flow_mod(datapath, flow_info, dst_port, bp_port_)
                                    # backward_ffg
                                    self.send_group_mod(datapath, self.gid+1, src_port, bp_port)
                                    self.send_flow_mod(datapath, back_info, dst_port, src_port,
                                                       self.gid+1)
                                    self.send_flow_mod(datapath, back_info, bp_port_, src_port,
                                                       self.gid+1)
                                    break
                            else:
                                if m == len_cir-1 :
                                    f =1
                                    print('inter_cir_100')
                                    # forward_wildcard
                                    self.send_flow_mod(datapath, flow_info, src_port, dst_port)
                                    self.send_flow_mod(datapath, flow_info, bp_port, dst_port)
                                    # backward_ffg
                                    self.send_group_mod(datapath, self.gid, src_port, bp_port)
                                    self.send_flow_mod(datapath, back_info, dst_port, src_port,
                                                       self.gid)
                                      # match return packets
                                    self.send_flow_mod(datapath, back_info, src_port, bp_port)
                        if f == 1:
                            break
                    elif path[i-1] in cir_list[j] and path[i] in cir_list[j] and path[i+1] in cir_list[j]:
                        print('inter_circle_11:', cir_list[j])
                        bp_cir_ = cir_list[j]
                        # forward_ffg
                        self.send_group_mod(datapath, self.gid, dst_port,
                                            datapath.ofproto.OFPP_IN_PORT, src_port)
                        self.send_flow_mod(datapath, flow_info, src_port, dst_port,
                                           self.gid)
                          # match return packets
                        self.send_flow_mod(datapath, flow_info, dst_port, src_port)
                        # backward_ffg
                        self.send_group_mod(datapath, self.gid+1, src_port,
                                            datapath.ofproto.OFPP_IN_PORT, dst_port)
                        self.send_flow_mod(datapath, back_info, dst_port, src_port,
                                           self.gid+1)
                          # match return packets
                        self.send_flow_mod(datapath, back_info, src_port, dst_port)
                        #datapath_ = datapaths[path[i-1]]
                        #p_ = bp_cir_.index(path[i-1])
                        #try:
                        #    if path[i] == bp_cir_[p_+1]:
                        #        bp_ = bp_cir_[p_-1]
                        #    else:
                        #        bp_ = bp_cir_[p_+1]
                        #except IndexError:
                        #    if path[i+1] == bp_cir_[0]:
                        #        bp_ = bp_cir_[p_-1]
                        #    else:
                        #        bp_ = bp_cir_[0]
                        #bp_port_ = self.get_port_pair_from_link(link_to_port,
                        #                                        path[i-1], bp_)[0]
                        #self.send_flow_mod(datapath_, flow_info, port_pair[0], bp_port_)
                        break
                    elif path[i-1] not in cir_list[j] and path[i] in cir_list[j] and path[i+1] in cir_list[j]:
                        cir_01 = cir_list[j]
                        if j == len_cir-1:
                                p = cir_list[j].index(path[i])
                                print('inter_circle_01:', cir_01)
                                bp_cir = cir_01
                                if bp_cir in path_cir:
                                    pass
                                else:
                                    path_cir.append(bp_cir)
                                    cir_cnt += 1
                                    try:
                                        if path[i+1] == bp_cir[p+1]:
                                            bp = bp_cir[p-1]
                                            cir_dir.append(-1)
                                        else:
                                            bp = bp_cir[p+1]
                                            cir_dir.append(1)
                                    except IndexError:
                                        if path[i+1] == bp_cir[0]:
                                            bp = bp_cir[p-1]
                                            cir_dir.append(-1)
                                        else:
                                            bp = bp_cir[0]
                                            cir_dir.append(1)
                                bp_port = self.get_port_pair_from_link(link_to_port,
                                                                        path[i], bp)[0]
                                print('inter_dp, p, bp,bp_port:', path[i], p,  bp, bp_port)
                                # forward_ffg
                                self.send_group_mod(datapath, self.gid, dst_port, bp_port)
                                self.send_flow_mod(datapath, flow_info, src_port, dst_port,
                                                   self.gid)
                                # match return packets
                                self.send_flow_mod(datapath, flow_info, dst_port, bp_port)
                                # backward_wildcard
                                self.send_flow_mod(datapath, back_info, bp_port, src_port)
                                self.send_flow_mod(datapath, back_info, dst_port, src_port)
                                break

                    elif j == len_cir-1:
                        if len(cir_01) == 0:
                            print('inter_circle_00')
                            self.send_flow_mod(datapath, flow_info, src_port, dst_port)
                            self.send_flow_mod(datapath, back_info, dst_port, src_port)
                        else:
                            print('inter_circle_01:', cir_01)
                            p = cir_01.index(path[i])
                            bp_cir = cir_01
                            if bp_cir in path_cir:
                                pass
                            else:
                                path_cir.append(bp_cir)
                                cir_cnt += 1
                                try:
                                    if path[i+1] == bp_cir[p+1]:
                                        bp = bp_cir[p-1]
                                        cir_dir.append(-1)
                                    else:
                                        bp = bp_cir[p+1]
                                        cir_dir.append(1)
                                except IndexError:
                                    if path[i+1] == bp_cir[0]:
                                        bp = bp_cir[p-1]
                                        cir_dir.append(-1)
                                    else:
                                        bp = bp_cir[0]
                                        cir_dir.append(1)
                            bp_port = self.get_port_pair_from_link(link_to_port,
                                                                    path[i], bp)[0]
                            print('inter_dp, p, bp,bp_port:', path[i], p,  bp, bp_port)
                            # forward_ffg
                            self.send_group_mod(datapath, self.gid, dst_port, bp_port)
                            self.send_flow_mod(datapath, flow_info, src_port, dst_port,
                                               self.gid)
                            # match return packets
                            self.send_flow_mod(datapath, flow_info, dst_port, bp_port)
                            # backward_wildcard
                            self.send_flow_mod(datapath, back_info, bp_port, src_port)
                            self.send_flow_mod(datapath, back_info, dst_port, src_port)


        ##--------bp_dp---------------
        print('\npath_cir:\n', path_cir)
        for j in range(len(path_cir)):
            for i in path_cir[j]:
                if i in path:
                    pass
                else:
                    p = path_cir[j].index(i)
                    print("bp_i, path_cir, p, dir:", i, path_cir[j], p, cir_dir[j] )
                    #print('i:', i)
                    try:
                        port = self.get_port_pair_from_link(link_to_port,
                                                   path_cir[j][p-cir_dir[j]], path_cir[j][p])
                    except IndexError:
                        port = self.get_port_pair_from_link(link_to_port,
                                                   path_cir[j][0], path_cir[j][p])
                    try:
                        port_next = self.get_port_pair_from_link(link_to_port,
                                                   path_cir[j][p], path_cir[j][p+cir_dir[j]])
                    except IndexError:
                        port_next = self.get_port_pair_from_link(link_to_port,
                                               path_cir[j][p], path_cir[j][0])

                    if port and port_next:
                        src_port, dst_port = port[1], port_next[0]
                        datapath = datapaths[path_cir[j][p]]
                        self.send_flow_mod(datapath, flow_info, src_port, dst_port)
                        self.send_flow_mod(datapath, back_info, dst_port, src_port)
                        self.logger.debug("inter_link of bp flow install")


    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        """
            To calculate shortest forwarding path and install them into datapaths.

        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)
        if result:
            src_sw, dst_sw = result[0], result[1]
            if dst_sw:
                # Path has already calculated, just get it.
                paths = self.get_path(src_sw, dst_sw, weight=self.weight)
                print('paths', paths)
                path_0 = paths[0]
                self.logger.info("[PATH]%s<-->%s: %s" % (ip_src, ip_dst, path_0))
                self.logger.info('gid%s' % self.gid)
                flow_info = (eth_type, ip_src, ip_dst, in_port)
                # install flow entries to datapath along side the path.
                self.install_flow(self.datapaths,
                                  self.awareness.link_to_port,
                                  self.awareness.cir_list,
                                  self.awareness.access_table, paths,
                                  flow_info, msg.buffer_id, msg.data)
        return

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
            In packet_in handler, we need to learn access_table by ARP.
            Therefore, the first packet from UNKOWN host MUST be ARP.
        '''
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        lldp_pkt = pkt.get_protocol(lldp.lldp)
        eth = pkt.get_protocol(ethernet.ethernet)

        #if isinstance(lldp_pkt, lldp.lldp):
        #    print ('^^^   LLDP ^^^^')

        if isinstance(arp_pkt, arp.arp):
            print('\nARP: packet in switch', datapath.id, 'in_port:', in_port,
                  'arp_src:', arp_pkt.src_ip, 'arp_dst:', arp_pkt.dst_ip)

            self.logger.debug("ARP processing")
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        if isinstance(ip_pkt, ipv4.ipv4):
            self.logger.debug("IPV4 processing")
            in_port = msg.match['in_port']
            if len(pkt.get_protocols(ethernet.ethernet)):
                print('\n***** IPv4: packet in switch', datapath.id, 'in_port:', in_port,
                         'src:', ip_pkt.src, 'dst:', ip_pkt.dst)
                self.gid += 2
                eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
                self.shortest_forwarding(msg, eth_type, ip_pkt.src, ip_pkt.dst)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, 
                                             MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _error_msg_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        err_type = int(msg.type)
        err_code = int(msg.code)
        print('error_msg:', dpid,err_type, err_code)



