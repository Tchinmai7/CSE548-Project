from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
log = core.getLogger()

class L3Firewall (object):
    firewall_rules = []
    def setup_flow_for_proto(self, nw_proto, dl_type):
        """
        generic flow-installing function used for ICMP and ARP packet flows
        """
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        match.nw_src = None
        match.nw_dst = None
        match.tp_src = None
        match.tp_dst = None
        match.nw_proto = nw_proto  # 1 for ICMP or ARP opcode
        match.dl_type = dl_type
        msg.match = match
        msg.hard_timeout = 0
        msg.soft_timeout = 0
        msg.priority = 32768
        action = of.ofp_action_output(port=of.OFPP_NORMAL)
        msg.actions.append(action)
        self.connection.send(msg)


    def __init__(self, connection):

	# Parse all firewall rules and put them in a list
        self.parse_firewall_rules()
        self.connection = connection
        connection.addListeners(self)

	# Allow ARP, ICMP by default
        self.setup_flow_for_proto(pkt.ipv4.ICMP_PROTOCOL, pkt.ethernet.IP_TYPE)
        self.setup_flow_for_proto(pkt.arp.REQUEST, pkt.ethernet.ARP_TYPE)
        self.setup_flow_for_proto(pkt.arp.REPLY, pkt.ethernet.ARP_TYPE)
        self.setup_flow_for_proto(pkt.arp.REV_REQUEST, pkt.ethernet.ARP_TYPE)
        self.setup_flow_for_proto(pkt.arp.REV_REPLY, pkt.ethernet.ARP_TYPE)

	# Insert flows from firewall list (bidirectional)
        for rule in self.firewall_rules:
            srcip, srcport, dstip, dstport = rule
            msg = of.ofp_flow_mod()
            match = of.ofp_match()

	    # Match IPv4 TCP packets,
	    match.nw_proto = pkt.ipv4.TCP_PROTOCOL
            match.dl_type = pkt.ethernet.IP_TYPE
            match.nw_dst = dstip
            match.nw_src = srcip
            if srcport != 'any':
                match.tp_src = int(srcport)
            else:
                match.tp_src = None
            if dstport != 'any':
                match.tp_dst = int(dstport)
            else:
                match.tp_dst = None

            msg.match = match
            msg.hard_timeout = 0
            msg.soft_timeout = 0
            msg.priority = 32768
            action = of.ofp_action_output(port=of.OFPP_CONTROLLER)
            msg.actions.append(action)
            self.connection.send(msg)
    	# add rule to drop all packets not defined by another rule
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        msg.match = match
        msg.hard_timeout = 0
        msg.soft_timeout = 0
        msg.priority = 1
        self.connection.send(msg)


    def resend_packet(self, packet):
        msg = of.ofp_packet_out()
        msg.data = packet
        out_port = of.OFPP_NORMAL
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def check_firewall_rules(self, fields):
        flag = False
	if len(fields) == 0:
	    return True
        for rule in self.firewall_rules:
            if IPAddr(rule[0]) == IPAddr(fields[0]):
                if fields[1] == rule[1] or rule[1] == 'any':
                    if IPAddr(rule[2]) == IPAddr(fields[2]):
                        if fields[3] == rule[3] or rule[3] == 'any':
                            flag = True
			    log.info("Match on rule < " +str(rule) + ">")
                            break
        return flag

    def install_flow_on_switch(self, nw_src, nw_dst, tp_src, tp_dst, allowed):
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        match.nw_src = nw_src
        match.nw_dst = nw_dst
        match.tp_src = int(tp_src)
        match.tp_dst = int(tp_dst)
        # all packets to match on are TCP
        match.nw_proto = pkt.ipv4.TCP_PROTOCOL
        # specify all packets as IP
        match.dl_type = pkt.ethernet.IP_TYPE
        msg.match = match
        msg.hard_timeout = 0
        msg.idle_timeout = 180
        msg.priority = 49152
        if allowed:
	    action = of.ofp_action_output(port = of.OFPP_NORMAL)
	    msg.actions.append(action)
        self.connection.send(msg)

    def install_packet_flow(self, packet, packet_in, allowed):
        ip_packet = packet.payload
        tcp_packet = ip_packet.payload
        # install the forward flow
        self.install_flow_on_switch(ip_packet.srcip, ip_packet.dstip, tcp_packet.srcport, tcp_packet.dstport, allowed)
        # install the reverse flow
        self.install_flow_on_switch(ip_packet.dstip, ip_packet.srcip, tcp_packet.dstport, tcp_packet.srcport, allowed)
        self.resend_packet(packet)


    def l3_firewall(self, packet, packet_in):
        # Bother only about IP packets
	if packet.find('ipv4') is not None:
          ip_packet = packet.payload
	  # IF its not TCP, don't care.
          if ip_packet.protocol == ip_packet.TCP_PROTOCOL:
            tcp_packet = ip_packet.payload
	    # extract necessary fields from the packet
            fields = [str(ip_packet.srcip), str(tcp_packet.srcport), str(ip_packet.dstip), str(tcp_packet.dstport)]
	# Verify if the packet is allowed according to our rules
       	  if self.check_firewall_rules(fields):
      	       allowed = True
          else:
               allowed = False
        # install the flows
          self.install_packet_flow(packet, packet_in, allowed)


    def _handle_PacketIn (self, event):
        """
        Handles packet in messages from the switch.
        """
        packet = event.parsed # This is the parsed packet data.
        if not packet.parsed:
          log.warning("Ignoring incomplete packet")
          return
        packet_in = event.ofp # The actual ofp_packet_in message.
        self.l3_firewall(packet, packet_in)

    def parse_firewall_rules(self):
	with open('/home/ubuntu/Desktop/firewall-policy.config') as fin:
            for line in fin:
		line = line.rstrip()
                rule = line.split(" ")
                if (len(rule) > 0):
                    self.firewall_rules.append(rule)
		    # now time to append reverse also
		    srcip, srcport, dstip, dstport = rule
                    rev_rule = [ dstip, dstport, srcip, srcport]
                    self.firewall_rules.append(rev_rule)

def launch ():
  def start_firewall (event):
    L3Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_firewall)
