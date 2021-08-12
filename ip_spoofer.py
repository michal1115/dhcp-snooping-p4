import sys, os, time, argparse

from scapy.all import sniff, sendp, get_if_list, get_if_hwaddr, get_if_addr
from scapy.all import Ether, ARP, IP, ICMP, UDP, Raw

INTERFACE = 'eth0'


if __name__ == "__main__":
    ether = Ether(src="08:00:00:00:00:04", dst="08:00:00:00:00:01")
    ip = IP(src="10.0.0.112", dst="10.0.0.111")
    udp = UDP(sport=10000, dport=10000)
    data = Raw(load=b"You should not receive it!")
    packet = ether / ip / udp / data
    sendp(packet, iface='eth0', verbose=False)