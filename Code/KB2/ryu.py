from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, icmp
import ipaddress
from datetime import datetime, time

# Config
ROLE_SUBNETS = {
    '10.0.1.0/24': 'Sales',
    '10.0.2.0/24': 'IT',
    '10.0.4.0/24': 'Visitor'
}

APP_SERVER_SUBNET = '10.0.3.0/24'

WORK_START = time(8, 0)
WORK_END   = time(16, 30)

READ_PORTS  = [80]  # port dùng cho read file
WRITE_PORTS = [22]  # port dùng cho write file

class PolicyRBAC(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.role_networks = {ipaddress.ip_network(k): v for k, v in ROLE_SUBNETS.items()}
        self.app_net = ipaddress.ip_network(APP_SERVER_SUBNET)

    def _get_role(self, ip):
        try:
            ipaddr = ipaddress.ip_address(ip)
            if ipaddr in self.app_net:
                return 'AppServer'
            for net, role in self.role_networks.items():
                if ipaddr in net:
                    return role
            return 'Unknown'
        except:
            return 'Unknown'

    def _in_work_time(self):
        now = datetime.now().time()
        return WORK_START <= now <= WORK_END


    def add_flow(self, dp, priority, match, actions, idle=120):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle
        ))

    def add_drop(self, dp, match, idle=120):
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp,
            priority=200,
            match=match,
            instructions=[],
            idle_timeout=idle
        ))


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER)]
        self.add_flow(dp, 0, match, actions)


    def check_policy(self, src_ip, dst_ip, dst_port):
        role = self._get_role(src_ip)

        if ipaddress.ip_address(dst_ip) in self.app_net:
            if role == 'Visitor':
                return False, "Visitor denied access to AppServer"

            if role == 'Sales':
                if not self._in_work_time():
                    return False, "Sales outside work time"
                if dst_port in READ_PORTS:
                    return True, "Sales READ secret.txt"
                return False, "Sales WRITE/EXEC denied"

            if role == 'IT':
                if dst_port in READ_PORTS + WRITE_PORTS:
                    return True, "IT full access"
                return False, "IT denied non-file port"

        return True, "Internal allow"


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']
        dpid = dp.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP
        if eth.ethertype == 0x88cc:
            return

        # ARP, ICMP always allowed
        if pkt.get_protocol(arp.arp) or pkt.get_protocol(icmp.icmp):
            out = ofp.OFPP_FLOOD
            dp.send_msg(parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=[parser.OFPActionOutput(out)],
                data=msg.data
            ))
            return


        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if not ip_pkt:
            dp.send_msg(parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=msg.data
            ))
            return

        dst_port = tcp_pkt.dst_port if tcp_pkt else 0
        allowed, reason = self.check_policy(ip_pkt.src, ip_pkt.dst, dst_port)

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_pkt.src,
            ipv4_dst=ip_pkt.dst,
            ip_proto=6,
            tcp_dst=dst_port
        )

        if allowed:
            self.add_flow(dp, 10, match, actions)
            self.logger.info("ALLOW %s(%s) → %s:%s | %s",
                             ip_pkt.src, self._get_role(ip_pkt.src),
                             ip_pkt.dst, dst_port, reason)
        else:
            self.add_drop(dp, match)
            self.logger.warning("DENY %s(%s) → %s:%s | %s",
                                ip_pkt.src, self._get_role(ip_pkt.src),
                                ip_pkt.dst, dst_port, reason)
            return

        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=msg.data
        ))
