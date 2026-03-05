#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp
import ipaddress

# ===== CẤU HÌNH ROLE DỰA TRÊN SUBNET =====
ROLE_SUBNETS = {
    '10.0.1.0/24': 'Sales',      # Lớp mạng Sales (VD: 10.0.1.11, 10.0.1.12, ...)
    '10.0.2.0/24': 'IT',         # Lớp mạng IT (VD: 10.0.2.11, 10.0.2.12, ...)
    '10.0.4.0/24': 'Visitor'     # Lớp mạng Visitor (VD: 10.0.4.21, 10.0.4.22, ...)
}

# Subnet của AppServer
APP_SERVER_SUBNET = '10.0.3.0/24'  # VD: 10.0.3.10, 10.0.3.11, ...

# Vai trò được phép truy cập AppServer
ALLOWED_ROLES = ['Sales', 'IT']

class RoleAccessControl(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RoleAccessControl, self).__init__(*args, **kwargs)
        # MAC to port mapping cho mỗi switch
        self.mac_to_port = {}
        # MAC to IP mapping để xác định role
        self.mac_to_ip = {}
        # Lưu trạng thái các flow đã từ chối để tránh log spam
        self.blocked_flows = set()
        # Parse subnets thành objects
        self.role_networks = {ipaddress.ip_network(subnet): role 
                             for subnet, role in ROLE_SUBNETS.items()}
        self.app_server_network = ipaddress.ip_network(APP_SERVER_SUBNET)

    def _get_role_from_ip(self, ip_str):
        if not ip_str:
            return 'Unknown'
        
        try:
            ip_addr = ipaddress.ip_address(ip_str)
            
            # Kiểm tra có phải AppServer không
            if ip_addr in self.app_server_network:
                return 'AppServer'
            
            # Kiểm tra thuộc subnet nào
            for network, role in self.role_networks.items():
                if ip_addr in network:
                    return role
            
            # Không thuộc subnet nào đã định nghĩa
            return 'Unknown'
        except ValueError:
            return 'Unknown'

    def _is_app_server(self, ip_str):
        if not ip_str:
            return False
        try:
            ip_addr = ipaddress.ip_address(ip_str)
            return ip_addr in self.app_server_network
        except ValueError:
            return False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss flow entry: gửi tất cả packet chưa match tới controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)
        
        self.logger.info("Switch %s connected - installed table-miss flow", datapath.id)

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def _add_drop_flow(self, datapath, priority, match, idle_timeout=0):
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=[],  # Không có action = DROP
                                idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def _extract_ip_from_packet(self, pkt):
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            return ip_pkt.src, ip_pkt.dst
        
        # Nếu là ARP packet
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            return arp_pkt.src_ip, arp_pkt.dst_ip
        
        return None, None

    def _check_access_policy(self, src_ip, dst_ip):
        role_src = self._get_role_from_ip(src_ip)
        is_dst_appserver = self._is_app_server(dst_ip)
        
        # Trường hợp 1: User → AppServer
        if is_dst_appserver:
            if role_src == 'Unknown':
                return False, f"[!!!]  SECURITY ALERT: Unknown device ({src_ip}) attempted to access AppServer", role_src
            elif role_src in ALLOWED_ROLES:
                return True, f"Role '{role_src}' is allowed to access AppServer", role_src
            elif role_src == 'AppServer':
                # AppServer tự ping chính nó (loopback) - cho phép
                return True, "AppServer internal traffic", role_src
            else:
                return False, f"Role '{role_src}' is DENIED access to AppServer", role_src
        
        # Trường hợp 2: AppServer → User (luôn cho phép - response traffic)
        if role_src == 'AppServer':
            return True, "AppServer response traffic is allowed", role_src
        
        # Trường hợp 3: Unknown → bất kỳ đâu (cảnh báo nhưng có thể cho phép traffic thông thường)
        if role_src == 'Unknown':
            return True, f"[*!]  Unknown device ({src_ip}) in network - normal traffic allowed", role_src
        
        # Trường hợp 4: User ↔ User (luôn cho phép)
        return True, "Normal inter-user traffic is allowed", role_src

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(data=msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # Bỏ qua LLDP packets
        if eth.ethertype == 0x88cc:
            return

        eth_src = eth.src
        eth_dst = eth.dst

        # Trích xuất IP từ packet
        src_ip, dst_ip = self._extract_ip_from_packet(pkt)

        # Học MAC → IP mapping
        if src_ip and eth_src:
            if eth_src not in self.mac_to_ip or self.mac_to_ip[eth_src] != src_ip:
                self.mac_to_ip[eth_src] = src_ip
                role = self._get_role_from_ip(src_ip)
                self.logger.info("Learned: MAC %s → IP %s (Role: %s)", eth_src, src_ip, role)

        # Khởi tạo MAC table cho switch này nếu chưa có
        self.mac_to_port.setdefault(dpid, {})

        # Học MAC address của source
        if eth_src not in self.mac_to_port[dpid]:
            self.logger.info("Switch %s: Learned MAC %s on port %s", dpid, eth_src, in_port)
        self.mac_to_port[dpid][eth_src] = in_port

        # Xác định output port
        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            out_port = ofp.OFPP_FLOOD

        # Nếu không có thông tin IP, cho phép (ARP, DHCP, ...)
        if not src_ip or not dst_ip:
            actions = [parser.OFPActionOutput(out_port)]
            data = None
            if msg.buffer_id == ofp.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath,
                                     buffer_id=msg.buffer_id,
                                     in_port=in_port,
                                     actions=actions,
                                     data=data)
            datapath.send_msg(out)
            return

        # ===== KIỂM TRA CHÍNH SÁCH RBAC =====
        allowed, reason, role_src = self._check_access_policy(src_ip, dst_ip)
        
        role_dst = self._get_role_from_ip(dst_ip)

        if allowed:
            # CHO PHÉP: Cài flow rule và forward packet
            actions = [parser.OFPActionOutput(out_port)]
            
            # Xác định priority dựa trên loại traffic
            if self._is_app_server(dst_ip):
                priority = 100  # User → AppServer (cao nhất)
                idle_timeout = 60
            elif role_src == 'AppServer':
                priority = 50   # AppServer → User
                idle_timeout = 60
            else:
                priority = 10   # User ↔ User
                idle_timeout = 30

            # Cài flow rule dựa trên IP (không phải MAC)
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
            self._add_flow(datapath, priority, match, actions, idle_timeout=idle_timeout)
            
            # Log với màu sắc khác cho Unknown
            if role_src == 'Unknown' or role_dst == 'Unknown':
                self.logger.warning("[*!]  ALLOW [S%s]: %s(%s) → %s(%s) | %s",
                               dpid, src_ip, role_src, dst_ip, role_dst, reason)
            else:
                self.logger.info("[*] ALLOW [S%s]: %s(%s) → %s(%s) | Port %s→%s | %s",
                               dpid, src_ip, role_src, dst_ip, role_dst, 
                               in_port, out_port, reason)

            # Gửi packet đi
            data = None
            if msg.buffer_id == ofp.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath,
                                     buffer_id=msg.buffer_id,
                                     in_port=in_port,
                                     actions=actions,
                                     data=data)
            datapath.send_msg(out)

        else:
            # TỪ CHỐI: Cài drop flow rule
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
            self._add_drop_flow(datapath, priority=100, match=match, idle_timeout=60)
            
            # Log chỉ lần đầu tiên để tránh spam
            flow_key = (dpid, src_ip, dst_ip)
            if flow_key not in self.blocked_flows:
                self.blocked_flows.add(flow_key)
                
                # Log CRITICAL nếu là Unknown trying to access AppServer
                if role_src == 'Unknown' and self._is_app_server(dst_ip):
                    self.logger.critical("[!!!] CRITICAL SECURITY ALERT [S%s]: BLOCKED Unknown device %s attempting to access AppServer %s!",
                                       dpid, src_ip, dst_ip)
                else:
                    self.logger.warning("[X] DENY [S%s]: %s(%s) → %s(%s) | %s",
                                      dpid, src_ip, role_src, dst_ip, role_dst, reason)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPPR_ADD:
            reason = 'ADD'
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
        else:
            reason = 'UNKNOWN'

        self.logger.info("Switch %s: Port %s %s", dp.id, msg.desc.port_no, reason)