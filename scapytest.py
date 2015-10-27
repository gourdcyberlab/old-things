#!/usr/bin/env python

from scapy.all import *

def testfxn(pkt):
	try:
		if pkt[IP].dst == '10.0.0.100' and pkt[ICMP]:
			newpkt = IP(dst='10.0.0.201')/pkt[ICMP]
			ans, uans = sr(newpkt, iface=eth0)
			newpkt = pkt[ETHER]/ans[0][1]
			pkt.dst = '10.1.0.100'
			pkt.src = '10.1.0.1'
			ans, uans = send(pkt,iface=eth1)
			print ans[0]
	except:
		pass
	print pkt.summary()

sniff(count = 5000, filter="icmp", prn = testfxn)

