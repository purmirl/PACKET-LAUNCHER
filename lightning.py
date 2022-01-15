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

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send

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
    return

# get udp packet function.
def get_udp_packet():
    return

# get icmp packet function.
def get_icmp_packet():
    return

# get arp packet function.
def get_arp_packet():
    # Ether src = ethernet source address
    # Ether dst = ethernet destination address

    # op (operation code) 1 = ARP Request
    # op (operation code) 2 = ARP Reply
    # op (operation code) 3 = RAPR Request
    # op (operation code) 4 = RARP Reply

    # hwsrc = sender hardware address
    # psrc = sender protocol address
    # hwpdst = target hardware address
    # pdst = target protocol address

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