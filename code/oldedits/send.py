#!/usr/bin/env python3

import socket
import sys
from time import sleep
import random
from scapy.all import IP, UDP,TCP, Ether, get_if_hwaddr, get_if_list, sendp
import copy
import scapy.volatile as v


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<4:
        print('pass 2 arguments: <destination> "<message>" <number of packets>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    #addr = ["136.9.20.17","18.60.19.50","150.60.27.80","10.10.13.3","143.12.14.57","58.69.32.4","145.25.65.8","22.58.94.9"]
    #pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=, tos=1) / UDP(dport=4321, sport=1234) / sys.argv[2]
    #pkt.show2()
    #hexdump(pkt)
    #dupPkt=Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=v.RandIP(), tos=1) / TCP(dport=1234, sport=49152) / sys.argv[2]
    dupPkt=[]
    try:
      count = 0
      for i in range(int(sys.argv[3])):
      	addr=v.RandIP()._fix()
      	pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr, tos=1) / TCP(dport=1234, sport=49152) / sys.argv[2]
      
      	dupPkt.append(pkt) #Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr, tos=1) / TCP(dport=1234, sport=49152) / sys.argv[2]
      	pkt.show2()
      	sendp(pkt, iface=iface)
      	count += 1
      	#sleep(1)
      for x in range(int(sys.argv[3])):
      	 print("---------------------------------------------------")
      	 dupPkt[x].show2()
      	 sendp(dupPkt[x], iface=iface)
      	 count += 1
      	#sleep(1)
      print("Total packets sent : " )
      print(count)
      print("Number of duplicate packets :")
      print(count - int(sys.argv[3]))
    except KeyboardInterrupt:
        raise


if __name__ == '__main__':
    main()
