#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# PySniff v1.0
# SYZYGY-DEV333
# Packet Sniffing tool written in Python
# Apache Version 2

import socket, sys
from struct import *

print "starting PySniff"

# Convert string of 6 characters of ethernet address into a dash seperated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

# create a AF_PACKET type raw socket (basically packet level)
# define ETH_P_ALL    0x0003        /* Every packet, be careful! */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + 'Message ' + msg[1]
    sys.exit()

# recieve a packet
while True:
    packet = s.recvfrom(65565)

    # packet string from tuple
    packet = packet[0]

    # parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    print 'Destination MAC : ' + eth_addr(packet[0:6])

    # parse ip packets, IP Protocol number = 8
    if eth_protocol == 8 :
        # parse IP header
        # take first 20 characters for ip header
        ip_header = packet[eth_length:20+eth_length]
        
        # now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        
        iph_length = ihl * 4
        
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        
        print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
        
        # TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]
            
            # now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)
            
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            
            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
            
            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
            
            # get data from the packet
            data = packet[h_size:]
            
            print 'Data : ' + data
            
        # UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]
            
            # now unpack them :)
            udph = unpack('!HHHH' , udp_header)
            
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
            
            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
            
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
            
            # get data from the packet
            data = packet[h_size:]
            
            print 'Data : ' + data
            
        # Some other IP packet
        else :
            print 'Error: Unknown Protocol'             
        print ''
