__author__ = 'azguard'
# Sniff only incomming TCP packet

import socket, sys
from struct import  *
#create an INET, Streaming socket

try:
    s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error, msg:
    print 'Socket could not be created. Error code :'+ str(msg[0]) + 'Message' + msg[1]
    sys.exit()

# receive a packet
while True:
    packet = s.recvfrom(65565)

    # Packet String from tuple
    packet = packet[0]

    # Take first 20 characters from the ip header

    ip_header = packet[0:20]

    # now unpack the charaters
    iph = unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl * 4

    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    # Print the packet information
    print 'Version : ' + str(version)+ 'IP Header Length : '+ str(ihl) + 'TTL : '+str(ttl)+'Protocol : '+str(protocol) + 'Source Address : '+str(s_addr) + 'Destination Address: '+str(d_addr)

    tcp_header = packet[iph_length:iph_length+20]

    # now unpack the header
    tcph = unpack('!HHLLBBHHH', tcp_header)

    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_lenght = doff_reserved >> 4

    # Print packet disection
    print 'Source Port : '+ str(source_port) + 'Destination Port : ' + str(dest_port) + ' Dequence Number : '+ str(sequence) + ' Acknowlwdgement : '+str(acknowledgement) + 'TCP header length : '+ str(tcph_lenght)

    h_size = iph_length + tcph_lenght * 4
    data_size = len(packet) - h_size

    # get data from the packet
    data = packet[h_size:]

    print 'Data : '+ data
    print 