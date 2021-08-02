import sys, os, time, argparse

from scapy.all import sniff, sendp, get_if_list, get_if_hwaddr, get_if_addr
from scapy.all import Ether, IP, UDP, DHCP, BOOTP
from dhcp_util import is_packet_dhcp_response, is_packet_dhcp_request, send_dhcp_request, send_dhcp_response, get_dhcp_message_type, get_dhcp_field

after_discover_sleep = None
cli_address_pool = []

def handle_packet(packet):
    if is_packet_dhcp_request(packet):
        print("handling")
        print(packet[BOOTP].chaddr)
        DHCP_MESSAGE_HANDLERS[get_dhcp_message_type(packet)](packet)

def handle_dhcp_discover(packet):
    print("Received dhcp discover")
    if len(cli_address_pool) > 0:
        time.sleep(after_discover_sleep)
        client_mac = packet[BOOTP].chaddr
        send_dhcp_response(get_dhcp_options('offer'), cli_address_pool[0], client_mac)

def handle_dhcp_request(packet):
    print("Received dhcp request")
    client_mac = packet[BOOTP].chaddr
    server_address = get_dhcp_field(packet, 'server_id')
    requested_client_address = get_dhcp_field(packet, 'requested_addr')
    if get_if_addr('eth0') == server_address:
        dhcp_option = 'ack' if requested_client_address in cli_address_pool else 'nak'
        cli_address_pool.remove(requested_client_address)
        send_dhcp_response(get_dhcp_options(dhcp_option), requested_client_address, client_mac)

def get_dhcp_options(message_type):
    return [('subnet_mask', '255.255.255.0'), ('router', get_if_addr('eth0')), ("server_id", get_if_addr('eth0')), ('message-type', message_type), ('end')]

def bind_ip_address_to_client(address):
    send_dhcp_response([('message-type', 'ack'), ('end')], cli_address_pool[0])

DHCP_MESSAGE_HANDLERS = {
    1: handle_dhcp_discover,
    3: handle_dhcp_request
}

if __name__ == '__main__':
    global after_discover_sleep, cli_address_pool
    parser = argparse.ArgumentParser()
    parser.add_argument('-sleep', type=int, help="Time that server will sleep after getting dhcp discover")
    parser.add_argument('address_pool', type=str, nargs="+", help="Client address pool for dhcp server")
    args = parser.parse_args()

    after_discover_sleep = args.sleep
    cli_address_pool = args.address_pool
    sniff(iface='eth0', prn=lambda p: handle_packet(p))
