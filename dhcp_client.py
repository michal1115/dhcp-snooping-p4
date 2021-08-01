import sys
import time
import subprocess

from scapy.all import Ether, IP, UDP, DHCP, BOOTP
from scapy.all import sendp, get_if_hwaddr, get_if_addr, sniff, get_if_raw_hwaddr
from scapy.all import str2mac
from dhcp_util import is_packet_dhcp_response, is_packet_dhcp_request, send_dhcp_request, send_dhcp_response, get_dhcp_message_type, get_dhcp_field
import binascii

#client will trust first server that will answer dhcp_discover
trusted_dhcp_server = None
requested_client_address = None

def handle_packet(packet):
    print("received")
    set_sender_as_trusted_dhcp_server_if_not_set(packet)
    if is_packet_dhcp_response(packet) and is_packet_from_trusted_dhcp_server(packet):
        message_type = get_dhcp_message_type(packet)
        print(message_type)
        DHCP_MESSAGE_HANDLERS[message_type](packet)

def set_sender_as_trusted_dhcp_server_if_not_set(packet):
    global trusted_dhcp_server
    if trusted_dhcp_server is None and is_packet_dhcp_response(packet):
        trusted_dhcp_server = packet[IP].src 

def is_packet_from_trusted_dhcp_server(packet):
    global trusted_dhcp_server
    return trusted_dhcp_server == packet[IP].src       

def handle_dhcp_offer(packet):
    global requested_client_address
    client_address = packet[BOOTP].ciaddr
    address_from_server = packet[BOOTP].yiaddr
    server_address = packet[BOOTP].siaddr
    gateway_addr = packet[BOOTP].giaddr
    print("Received packet")
    print(client_address)
    print(address_from_server)
    print(server_address)
    print(gateway_addr)
    requested_client_address = client_address
    send_dhcp_request([('message-type', "request"), ("server_id", server_address), ("requested_addr", client_address), ('end')])

def handle_dhcp_ack(packet):
    global requested_client_address
    configure_from_dhcp(packet)

def configure_from_dhcp(packet):
    global requested_client_address
    subnet_mask = get_dhcp_field(packet, 'subnet_mask')
    default_gateway = get_dhcp_field(packet, "router")

    set_ip_addr_cmd = "ifconfig eth0 " + requested_client_address + " netmask " + subnet_mask + " up"
    subprocess.call(set_ip_addr_cmd, shell=True)

    set_default_gateway_cmd = "route add default gw " + default_gateway
    subprocess.call(set_default_gateway_cmd, shell=True)
    exit(0)

def handle_dhcp_nak(packet):
    global requested_client_address
    required_client_address = None

DHCP_MESSAGE_HANDLERS = {
    2: handle_dhcp_offer,
    5: handle_dhcp_ack,
    6: handle_dhcp_nak
}

if __name__ == '__main__':
    send_dhcp_request([('message-type', "discover"), ('end')])
    print("starting sniffing")
    sniff(iface='eth0', prn=lambda p: handle_packet(p))
