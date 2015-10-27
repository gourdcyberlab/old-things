from scapy.all import *
#import nfqueue, socket

#q = nfqueue.queue()
#q.open()
#q.bind(socket.AF_INET)
#q.set_callback(ReplyAll)
#q.create_queue(0)

#try:
#	q.try_run()
#except KeyboardInterrupt:
#	print "Exiting..."
#q.unbind(socket.AF_INET)
#q.close()

def pingReply(pkt):
	
	print ':::PING REPLY:::'
	if pkt[2].type == 8:
		temp = pkt[1].dst
		#pinger.src = '10.0.0.1'
		pinger.dst = '10.0.0.200'
		del pinger.chksum
		print 'PINGER:'
		print pinger.summary()
		ans, unans = sr(pinger)
		print 'REPLY:'
		print ans[0][1].summary()
		reply = ans[0][1]
		#reply.dst = pkt[1].src
		reply.src = temp
		del reply.chksum
		send(reply)
		print 'Reply Sent!'
		reply.summary()
		print '\n\n'
	else:
		print pkt.summary()
		print "SCRAPPED"

def ReplyAll(pkt):
	#if ICMP in pkt:
	#	pingReply(pkt)
	#print pkt.summary()	
	#print pkt.display()
	if TCP in pkt and pkt[IP].src == '10.1.0.100':
		temp=pkt[1]
		dst=pkt[IP].src
		src=pkt[IP].dst
		temp[IP].dst='10.0.0.1'
		ans, unans=sr(temp)
		for response in ans:
			ans.dst=dst
			ans.src=src
			del ans.chksum
			send(ans)
			print 'Reply sent!'
	if ICMP in pkt and pkt[IP].src == '10.1.0.100':
		temp = pkt[1].dst
		msg = pkt[1]
		del msg.chksum
		msg.dst = '10.0.0.200'
		#print ':::::FAKE MSG::::::'
		#print msg.summary()
		ans, unans = sr(msg)
		for response in ans:
			#print 'RESPONSE:::'
			toAtk = response[1]
			#print toAtk.show()
			toAtk.src = temp 
			#print 'MSG TO ATTACKER:::'
			#print toAtk.summary()
			del toAtk.chksum
			send(toAtk)
			print 'Reply Sent!'
	

sniff(prn=ReplyAll, iface='eth1', store=0)
