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

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandShort, RandString

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
""" @:get TCP packet function
01. IP
    01-1. src = source ip address
    01-2. dst = destination ip address
"""
def get_tcp_packet():
    source_ip_address = ""
    destination_ip_address = ""
    tcp_packet = IP(src = source_ip_address, dst = destination_ip_address) / TCP(sport=RandShort(), dport=80, seq=1000, ack=1000, flags="S")
    return

""" @:get UDP packet function
01. IP
    01-1. src = source ip address
    01-2. dst = destination ip address
02. UDP
    02-1. sport = source port number
    02-2. dport = destination port number
    02-3. data_size = packet's data size
"""
def get_udp_packet():
    source_ip_address = "" # string
    destination_ip_address = "" # string
    source_port = 1 # integer
    destination_port = 1 # integer
    data_size = 0 # integer
    udp_packet = IP(src = source_ip_address, dst = destination_ip_address)/ \
                 UDP(sport = source_port, dport = destination_port)/ \
                 Raw(RandString(size = data_size))
    return udp_packet

# get icmp packet function.
""" @:get ICMP packet function
01. IP
    01-1. src = source ip address
    01-2. dst = destination ip address
02. ICMP
    02-1. type : ICMP type
        if type 0 : ICMP echo reply
        if type 3 : ICMP destination unreachable
        if type 4 : ICMP source quench, not standard
        if type 5 : ICMP redirect
        if type 8 : ICMP echo request
        if type 9 : ICMP router advertisement
        if type 10 : ICMP router solicitation
        if type 11 : ICMP time exceeded
        if type 12 : ICMP parameter problem
    02-2. code : ICMP type message
        if type 0, code 0 : network unreachable
        if type 0, code 1 : host unreachable
        if type 0, code 2 : protocol unreachable
        if type 0, code 3 : port unreachable
"""
def get_icmp_packet():
    source_ip_address = "" # string
    destination_ip_address = "" # string
    message_type = 0 # integer
    data_size = 0 # integer
    icmp_packet = IP(src = source_ip_address, dst = destination_ip_address)/ \
                  ICMP(type = message_type)/ \
                  Raw(RandString(size = data_size))
    return icmp_packet

""" @:get ARP packet function
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
    arp_packet = Ether(dst = "ff:ff:ff:ff:ff:ff")/ \
                 ARP(op = 1, pdst = "192.168.35.1")
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