from scapy.all import *
def icmp(pkt):
	#Pulls the destination, source, sequence no. and load
	#For generated packet
	dst=pkt[1].src
	src=pkt[1].dst
	seq=pkt[2].seq
	load=pkt[3].load

	#Opens the template and puts the hashstring into a variable
	packet=open('pingPacket.txt', 'r').read()

	#Converts the hashstring into a packet template
	reply=IP(packet)

	#Modifies the template to show correct destination, source, sequence no.
	#Load and ICMP id
	reply.dst=dst
	reply.src=src
	reply.seq=seq
	reply[2].load=load
	reply[1].id=pkt[2].id

	#Deletes the checksums 
	#These will be added automatically by Scapy when send() is called
	del reply.chksum
	del reply[1].chksum

	#Sends the generated packet
	send(reply)

	#Lets the experimentor know that the packet has been sent
	print 'Reply sent!'

def tcp(pkt):
	packet=open('tcpPacket.txt','r').read()
	reply=IP(packet)
	send(reply)
	print 'Reply Sent!'

#This function will be added to to respond to the various types of packets 
#As of <July 29, 2014> Responds to: ICMP
def replyAll(pkt):
	if ICMP in pkt:
		icmp(pkt)
	if TCP in pkt:
		tcp(pkt)	
sniff(filter = 'src 10.1.0.100', prn=replyAll, iface='eth1', store=0)
	
