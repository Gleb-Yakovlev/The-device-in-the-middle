from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import Raw
from scapy.all import sendp
from scapy.all import sniff
import datetime
import time
import socket

import os

# cd E:\PROGRAMS\megaSniffer
# python sniff_copy_BKT.py
# pyinstaller --onefile sniff.py

mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mySocket.bind(('localhost', 0))
print(mySocket.getsockname()[0])

filename = "sf.txt"



LEFT_MAC_ADRESS = LEFT_IP_ADRESS_STRING = RIGHT_MAC_ADRESS = RIGHT_IP_ADRESS_STRING = SNIFFER_MAC_address = SNIFFER_IP_address = 0
LEFT_PORT = 0
SNIFFER_PORT = 12345

# ----------change data----------#
change_data_array = []
SKAF_data = 0
# ----------change data----------#

# ----------load----------#


def load():
    global LEFT_MAC_ADRESS, LEFT_IP_ADRESS_STRING, RIGHT_MAC_ADRESS, RIGHT_IP_ADRESS_STRING, SNIFFER_MAC_address, SNIFFER_IP_address
    file = open(filename, "r")
    print(file)
    lines = file.readlines()
    print(lines)
    LEFT_MAC_ADRESS = lines[0].strip()
    LEFT_IP_ADRESS_STRING = lines[1].strip()
    RIGHT_MAC_ADRESS = lines[2].strip()
    RIGHT_IP_ADRESS_STRING = lines[3].strip()
    SNIFFER_MAC_address = lines[4].strip()
    SNIFFER_IP_address = lines[5].strip()
    file.close()



def load_autochange():
    global change_data_array
    file = open("autochangeFile.txt", "r")
    file.flush()
    lines = file.readlines()
    for line in lines:
        l = line.strip().split('|SEP|')
        change_data_array.append([l[0], l[1]])
    print("read autochangeFile")
    file.close()

load_autochange()
load()
# ----------load----------#


# ----------uddate ARP table----------#

def arp():
    # stringMAC = "2d-2d-2d-2d-2d-2d"
    global LEFT_MAC_ADRESS
    global LEFT_IP_ADRESS_STRING
    global RIGHT_MAC_ADRESS
    global RIGHT_IP_ADRESS_STRING
    global SNIFFER_MAC_address
    global SNIFFER_IP_address

    command1 = "arp -s " + LEFT_IP_ADRESS_STRING + " " + LEFT_MAC_ADRESS
    print("command : ", command1)
    os.system(command1)
    command2 = "arp -s " + RIGHT_IP_ADRESS_STRING + " " + RIGHT_MAC_ADRESS
    print("command : ", command2)
    os.system(command2)
    command3 = "arp -s " + SNIFFER_IP_address + " " + SNIFFER_MAC_address
    print("command : ", command3)
    os.system(command3)

arp()
# ----------uddate ARP table----------#

# ----------send packet----------#
def to_mac_colon(mac):
    return mac.replace("-", ":")

n = 1

def send_packet(packet, side):
    global LEFT_RIGHT_count
    global RIGHT_LEFT_count
    global SNIFFER_MAC_address
    global SNIFFER_IP_address
    global LEFT_PORT
    global SNIFFER_PORT
    global change_data_array
    global n
    global SKAF_data



    if side == "left-right":
        newPacket = packet
        data = str(packet[Raw].load.hex())


        newPacket[Ether].src = to_mac_colon(SNIFFER_MAC_address)
        newPacket[IP].src = SNIFFER_IP_address
       #print(side)
        newPacket[Ether].dst = to_mac_colon(RIGHT_MAC_ADRESS)
        newPacket[IP].dst = RIGHT_IP_ADRESS_STRING
        LEFT_PORT = packet[UDP].sport
        newPacket[UDP].sport = SNIFFER_PORT
        # if data == "0240082003":
        #     data = "0240000003"
        #     newPacket = Ether(src = to_mac_colon(SNIFFER_MAC_address), dst =to_mac_colon(RIGHT_MAC_ADRESS), type = 0x0800)/IP (src = SNIFFER_IP_address, dst = RIGHT_IP_ADRESS_STRING)/UDP(sport = 12345, dport = 9000)/bytes.fromhex(data)
        
    elif side == "right-left":
        data = str(packet[Raw].load.hex())
        data = next((change_data_array[i][1] for i in range(len(change_data_array)) if change_data_array[i][0] == data), None)
        if data == None:
            data = str(packet[Raw].load.hex())
        print(data)
        # if data == change_data_array[0][0]:
        #     data = change_data_array[0][1]
        #     print("podmena")
        newPacket = Ether(src = to_mac_colon(SNIFFER_MAC_address), dst =to_mac_colon(LEFT_MAC_ADRESS), type = 0x0800)/IP (src = SNIFFER_IP_address, dst = LEFT_IP_ADRESS_STRING)/UDP(sport = 9000, dport = LEFT_PORT)/bytes.fromhex(data)
        
        #newPacket = Ether(src = to_mac_colon(SNIFFER_MAC_address), dst =to_mac_colon(LEFT_MAC_ADRESS), type = 0x0800)/IP (src = SNIFFER_IP_address, dst = LEFT_IP_ADRESS_STRING)/UDP(sport = 9000, dport = LEFT_PORT)/packet[Raw]
        
    else:
        print("error side")
        return 0
    sendp(newPacket, verbose = "false", iface="Ethernet")    
    print(str(n) + " : ", datetime.datetime.now())
    n += 1
    print(newPacket)
    # for p in newPacket:
    #     a = p.show(dump=True)
    #     print(type(a))
    #     print(a)

# ----------send packet----------#

# ----------sniff data----------#

def packet_handler(packet):
    global LEFT_IP_ADRESS_STRING
    global RIGHT_IP_ADRESS_STRING
    global SNIFFER_IP_address
    # print("catch")
    # print(packet[IP].src)
    # print(packet[IP].dst)
    print("---------------")

    print("CATCH ", packet, " ", datetime.datetime.now())
    if packet[IP].dst == SNIFFER_IP_address:
        if packet[IP].src == LEFT_IP_ADRESS_STRING:
            send_packet(packet, "left-right")
        if packet[IP].src == RIGHT_IP_ADRESS_STRING: 
            send_packet(packet, "right-left")
               

def shiff_data():
    sniff(prn=packet_handler, filter = "ip dst " + SNIFFER_IP_address, iface="Ethernet")

print(LEFT_IP_ADRESS_STRING)
print(LEFT_MAC_ADRESS)
print(RIGHT_IP_ADRESS_STRING)
print(RIGHT_MAC_ADRESS)
print(SNIFFER_IP_address)
print(SNIFFER_MAC_address)

shiff_data()
# ----------sniff data----------#