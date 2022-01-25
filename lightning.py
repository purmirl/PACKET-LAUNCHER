"""
Copyright 2022~ PeTrA. All rights reserved.

Lightning Arrow Project (Simple Packet Launcher Script with Python Scapy by PeTrA. 2022~
LightningArrow 1.0
Language : Python3.8.2 on pycharm IDE
Library : Scapy2.4.3

@lightning.py
https://github.com/purmirl/PACKET-LAUNCHER/lightning.py

last update : 2022 JAN
"""

# import.
import time

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send
from scapy.volatile import RandShort

"""
@ packet launcher structure
 . def packet_launcher
 . def send one packet
 . def send many packets
"""
# packet launcher function.
def packet_launcher():
    packet = get_arp_packet()
    send_many_packets(packet, 10, 1)
    return

# send one packet.
def send_one_packet(_packet):
    send(_packet)
    return

# send many packets(_packet).
def send_many_packets(_packet, _number_of_packet, _time_interval):
    counter = 0
    while True:
        send(_packet)
        counter = counter + 1
        if counter == _number_of_packet:
            break
        time.sleep(int(_time_interval))
    return

"""
@ packet structure
 . def get tcp packet
 . def get udp packet
 . def get icmp packet
"""
# get tcp packet function.
def get_tcp_packet():
    tcp_packet = IP(src="", dst="") / TCP(sport=RandShort(), dport=80, seq=1000, ack=1000, flags="S")
    return

# get udp packet function.
def get_udp_packet():
    return

# get icmp packet function.
def get_icmp_packet():
    return

""" @:get arp packet function
01. Ether
    01-1. src : source mac address
    01-2. dst : destination mac address
        if arp request : set "ff:ff:ff:ff:ff:ff" or gateway mac address
02. ARP
    02-1. op : ARP operation code
        if ARP request : integer 1
        if ARP reply : integer 2
        if RARP request : integer 3
        if RARP reply : integer 4
    02-2. hwsrc : source (sender) mac address (hardware address)
    02-3. psrc : source (sender) ip address (protocol address)
    02-4. hwdst : destination (target) sender mac address (hardware address)
        if ARP request : set "00:00:00:00:00:00"
    02-5. pdst : destination (target) ip address (protocol address)
"""
def get_arp_packet():
    arp_packet = Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(op = 1, pdst = "192.168.35.1")
    return arp_packet

""" 
@ main structure
 . def main function    
"""
# main function
def main():
    packet_launcher()
    return

if __name__ == "__main__":
    main()