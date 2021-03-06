"""
Copyright 2022~ PeTrA. All rights reserved.

Lightning Arrow Project : Simple Packet Launcher Script with Python Scapy by PeTrA. 2022~
LightningArrow 1.0
Language : Python3.8.2 on pycharm IDE
Library : Scapy2.4.3

@lightning.py
https://github.com/purmirl/PACKET-LAUNCHER/lightning.py

last update : 2022 FEB
"""

import time

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandShort, RandString

""" @:packet launcher structure ↓ : packet_launcher, send_one_packet, send_many_packets
"""

""" @:packet launcher
"""
def packet_launcher():
    packet = get_arp_packet()
    send_many_packets(packet, 10, 1)
    return

""" @:send one packet
"""
def send_one_packet(_packet):
    send(_packet)
    return

""" @:send many packets
"""
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
    01-1. src = source_mac_address
    01-2. dst = destination_mac_address
        if arp request : set "ff:ff:ff:ff:ff:ff" or gateway mac address
02. ARP
    02-1. op = operation_code
        if ARP request : integer 1
        if ARP reply : integer 2
        if RARP request : integer 3
        if RARP reply : integer 4
    02-2. hwsrc = hardware_address_source (sender mac address)
    02-3. psrc = protocol_address_source (sender ip address)
    02-4. hwdst = hardware_address_destination (target mac address)
        if ARP request : set "00:00:00:00:00:00"
    02-5. pdst = protocol_address_destination (target ip address)
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
    01-1. src = source_ip_address
    01-2. dst = destination_ip_address
"""
def get_ip_packet():
    source_ip_address = "" # string, param : src
    destination_ip_address = "" # string, param : dst

    data_size = 0 # integer

    ip_packet = IP(src = source_ip_address, dst = destination_ip_address) / \
                Raw(RandString(size = data_size))

    return ip_packet

""" @:get ICMP packet function
01. IP
    01-1. src = source_ip_address
    01-2. dst = destination_ip_address
02. ICMP
    02-1. type = message_type
        if type 0 : ICMP echo reply
        if type 3 : ICMP destination unreachable
        if type 4 : ICMP source quench, not standard
        if type 5 : ICMP redirect
        if type 8 : ICMP echo request
        if type 9 : ICMP router advertisement
        if type 10 : ICMP router solicitation
        if type 11 : ICMP time exceeded
        if type 12 : ICMP parameter problem
"""
def get_icmp_packet():
    source_ip_address = "" # string, param : src
    destination_ip_address = "" # string, param : dst

    message_type = 0 # integer, param : type

    data_size = 0 # integer

    icmp_packet = IP(src = source_ip_address, dst = destination_ip_address)/ \
                  ICMP(type = message_type)/ \
                  Raw(RandString(size = data_size))

    return icmp_packet

""" @:get TCP packet function
01. IP
    01-1. src = source_ip_address
    01-2. dst = destination_ip_address
02. TCP
    02-1. sport = source_port
    02-2. dport = destination_port
    02-3. seq = sequence_number
    02-4. ack = ack_number
    02-5. flags = tcp_flags
        CWR : C / Congestion Window Reduced
        ECE : E / Explicit Congestion Notification (ECN) Echo
        URG : U / Urgent
        ACK : A / Acknowledgment
        PSH : P / Push
        RST : R / Reset
        SYN : S / Synchronize
        FIN : F / Finish
"""
def get_tcp_packet():
    source_ip_address = "" # string
    destination_ip_address = "" # string

    source_port = RandShort() # integer, param : sport
    destination_port = 80 # integer, param : dport
    sequence_number = 1000 # integer, param : seq
    ack_number = 1000 # integer, param : ack
    tcp_flags = "S" # string, param : flags

    data_size = 0 # integer

    tcp_packet = IP(src = source_ip_address, dst = destination_ip_address) / \
                 TCP(sport = source_port, dport = destination_port, seq = sequence_number, ack = ack_number, flags = tcp_flags) / \
                 Raw(RandString(size = data_size))

    return tcp_packet

""" @:get UDP packet function
01. IP
    01-1. src = source_ip_address
    01-2. dst = destination_ip_address
02. UDP
    02-1. sport = source_port
    02-2. dport = destination_port
"""
def get_udp_packet():
    source_ip_address = "" # string, param : src
    destination_ip_address = "" # string, param : dst

    source_port = 1 # integer, param : source_port
    destination_port = 1 # integer, param : destination_port

    data_size = 0 # integer

    udp_packet = IP(src = source_ip_address, dst = destination_ip_address)/ \
                 UDP(sport = source_port, dport = destination_port)/ \
                 Raw(RandString(size = data_size))

    return udp_packet

""" 
@ main structure
 . def main function    
"""
def main():
    packet_launcher()
    return

if __name__ == "__main__":
    main()