import sys
from scapy.all import *
from scapy.utils import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP, UDP 

pkts = rdpcap("test.pcap")
#print("TCP")
#scapy.ls(scapy.TCP)
#print("ICMP")
#scapy.ls(scapy.ICMP)
#print("IP")
#scapy.ls(scapy.IP)

for pkt in pkts:
    if pkt.haslayer("IP"):
        if pkt.haslayer("TCP"):
            #print(pkt[TCP].payload)
            pkt.remove_payload()
            print (pkt)
        elif pkt.haslayer("UDP"):
            pkt.remove_payload()
            print(pkt)
        else:
            pkt.remove_payload()
            print (pkt)

    #pkt_hex=scapy.bytes_hex(pkt)
    
    #print(pkt_hex)
    #pkt_bin = bin(int.from_bytes(pkt_hex, byteorder=sys.byteorder))
    #print(pkt_bin)
# Check the type of packet, there should only be data in TCP packets, UDP could also have them. Only have to check TCP before taking out payload, else do normal bin extract
