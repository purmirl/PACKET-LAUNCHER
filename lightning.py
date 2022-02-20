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
 . def send_one_packet
 . def send_many_packets
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

""" @:making packet function area ↓ : ARP, IP, ICMP, TCP, UDP
"""

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
    source_mac_address = "" # string, param : src
    destination_mac_address = "ff:ff:ff:ff:ff:ff" # string, param : dst

    operation_code = 1 # integer, param : op
    hardware_address_source = "" # string, param : hwsrc
    protocol_address_source = "" # string, param : psrc
    hardware_address_destination = "" # string, param : hwdst
    protocol_address_destination = "192.168.35.1" # string, param : pdst

    arp_packet = Ether(src = source_mac_address, dst = destination_mac_address)/ \
                 ARP(op = operation_code, pdst = protocol_address_destination)

    return arp_packet

""" @:get IP Packet function
01. IP
    01-1. src = source ip address
    01-2. dst = destination ip address
"""
def get_ip_packet():
    source_ip_address = ""
    destination_ip_address = ""

    data_size = 0 # integer

    ip_packet = IP(src = source_ip_address, dst = destination_ip_address) / \
                Raw(RandString(size = data_size))

    return ip_packet

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

""" @:get TCP packet function
01. IP
    01-1. src = source ip address
    01-2. dst = destination ip address
"""
def get_tcp_packet():
    source_ip_address = "" # string
    destination_ip_address = "" # string

    source_port = RandShort() # integer
    destination_port = 80 # integer
    sequence_number = 1000 # integer
    ack_number = 1000 # integer
    tcp_flags = "S"

    tcp_packet = IP(src = source_ip_address, dst = destination_ip_address) / \
                 TCP(sport = source_port, dport = destination_port, seq = sequence_number, ack = ack_number, flags = tcp_flags)

    return tcp_packet

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