#!/usr/bin/env python3

import socket
import sys
from time import sleep
import random
from scapy.all import IP, UDP,TCP, Ether, get_if_hwaddr, get_if_list, sendp, rdpcap, wrpcap
import copy
import scapy.volatile as v
import scapy.utils as r
import string
import random
import os.path
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
	if len(sys.argv)<2:
		print('pass 3 arguments: <pcap file name> <number of packets> and <space between duplicates>')
		exit(1)
	fname = sys.argv[1]
	iface = get_if()
	#print(sys.argv[2])
	if (os.path.isfile(fname) ):
		pkts = rdpcap(fname)
		pktNum = len(pkts)
		start = 0
		for c in range(pktNum+1) :
			#print(c)
			sendFlag = c%5
			if (sendFlag == 0) :
				sendp(pkts[start:c+1], iface=iface)
				start = c + 1
	else:
		#f = open(fname, "x")
		
		length = int(sys.argv[3])
		try:
			addrArr = []
			count = 0
			
			for i in range(int(sys.argv[2])):
				addr=v.RandIP()._fix()
				letters = string.ascii_lowercase
				randNum = random.randint(5,25)
				message = ''.join(random.choice(letters) for x in range(randNum))
				
				while (addr in addrArr) :
					addr=v.RandIP()._fix()
				addrArr.append(addr)
				
				pkt=Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr, tos=1) / TCP(dport=1234, sport=49152) / message
				wrpcap(fname, pkt, append=True)
				count += 1
				num = i % length
				if (num == 0):
					dupPkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr, tos=1) / TCP(dport=1234, sport=49152) / message
				if (num == (length - 1)) :
					wrpcap(fname, dupPkt, append=True) 
					count += 1

			pkts = rdpcap(fname)
			pktNum = len(pkts)
			start = 0
			for c in range(pktNum) :
				sendFlag = c%5
				if (sendFlag == 0) :
					sendp(pkts[start:c+1], iface=iface)
					start = c + 1
		except :
			raise


if __name__ == '__main__':
	main()
