from socket import * 
import os, sys, struct


def tcp_sniff(): 
	
	#Open up a raw socket, only TCP packets to be sniffed
	try:
		tcp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)

	except Exception, error:

		print "\n + Failed to create socket: %s \n" % error 
		sys.exit()
	
	
	
	tcp_packet = tcp_sock.recvfrom(1024) 
	
	#Get the source IP from recvfrom's second tuple member
	origin_addr = tcp_packet[1]
	
	#Ignore weird flag data and isolate only the IP address
	origin_addr = origin_addr[0]
	

	packet_data = tcp_packet[0]

	ip_header = packet_data[:20] 

	#unpack the header data 
	data = struct.unpack('!BBHHHBBH4s4s', ip_header)
	
	print data[0] >> 4 

	 

	   
	
	 


while 1:
	tcp_sniff() 
