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

from scapy.layers.l2 import ARP
from scapy.sendrecv import send

""" 
@ main structure
 . def main function    
"""
# main function
def main():
    return

if __name__ == "__main__":
    main()

"""
@ packet launcher structure
 . def packet_launcher
 . def send one packet
 . def send many packets
"""
# packet launcher function.
def packet_launcher(_packet):
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
    # op (operation code) 1 = ARP Request
    # op (operation code) 2 = ARP Reply
    # op (operation code) 3 = RAPR Request
    # op (operation code) 4 = RARP Reply
    arp_packet = ARP(op = ARP.who_has, )
    return