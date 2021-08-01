from scapy.all import Ether, IP, UDP, DHCP, BOOTP
from scapy.all import sendp, get_if_hwaddr, get_if_addr, sniff
from scapy.all import str2mac, get_if_raw_hwaddr
import binascii

def is_packet_dhcp_response(packet):
    return BOOTP in packet and packet[BOOTP].op == 2

def is_packet_dhcp_request(packet):
    return BOOTP in packet and packet[BOOTP].op == 1

def send_dhcp_request(options):
    src_mac = get_if_hwaddr('eth0')
    ether = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src="0.0.0.0", dst="255.255.255.255")
    udp = UDP(sport=68, dport=67)
    #bootp = BOOTP(op=1, chaddr=str2mac(get_if_raw_hwaddr('eth0')[1]))
    bootp = BOOTP(op=1, chaddr=binascii.unhexlify(get_if_hwaddr('eth0').replace(":", "")))
    dhcp = DHCP(options=options)
    packet = ether / ip / udp / bootp / dhcp
    sendp(packet, iface='eth0', verbose=False)

def send_dhcp_response(options, client_address, client_mac):
    src_mac = get_if_hwaddr('eth0')
    ether = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
    ip = IP(src=get_if_addr('eth0'), dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, chaddr=client_mac, ciaddr=client_address, yiaddr=client_address, siaddr=get_if_addr('eth0'), giaddr=get_if_addr('eth0'))
    dhcp = DHCP(options=options)
    packet = ether / ip / udp / bootp / dhcp
    sendp(packet, iface='eth0', verbose=False)
    
def get_dhcp_message_type(packet):
    return get_dhcp_field(packet, 'message-type')

def get_dhcp_field(packet, field):
    _, message_type = filter(lambda option: option[0] == field, packet[DHCP].options)[0]
    return message_type