from scapy.all import *

def display(pkt):
	print pkt.show()
	inp=raw_input("")
	if inp == 'S':
		save=str(pkt[1])
		open('tcpPacket.txt', 'w').write(save)

sniff(filter="src or dst 10.0.0.1", iface='eth1', store=0, prn=display)
