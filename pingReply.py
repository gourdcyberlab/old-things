from scapy.all import *

def pingReply(pkt):	
#	print ':::PING REPLY:::'
	if pkt[2].type == 8:
		temp = pkt[1].dst
		#print pkt.summary()
		#print pkt.src
		#print pkt[2]
		pinger = pkt[1]
		#pinger.src = '10.0.0.1'
		pinger.dst = '10.0.0.200'
		del pinger.chksum
		#print 'PINGER:'
		#print pinger.summary()
		ans, unans = sr(pinger)
		#print 'REPLY:'
		#print ans[0][1].summary()
		reply = ans[0][1]
		#reply.dst = pkt[1].src
		reply.src = temp
		del reply.chksum
		send(reply)
		print 'Reply Sent!'
#		print '\n\n'
		#create ping packet text file
		#open('pingPacket.txt', 'w').write(str(reply))
	else:
		print pkt.summary()
		print "SCRAPPED"

def ReplyAll(pkt):
	if ICMP in pkt:
		pingReply(pkt)	

sniff(filter = 'icmp and src 10.1.0.100',prn=ReplyAll, iface='eth1', 
store=0)
