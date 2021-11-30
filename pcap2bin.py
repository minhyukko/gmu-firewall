import sys
import getopt
from scapy.all import *
from scapy.utils import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP, UDP 

#print("TCP")
#scapy.ls(scapy.TCP)
#print("ICMP")
#scapy.ls(scapy.ICMP)
#print("IP")
#scapy.ls(scapy.IP)
def pcap_to_bin(inputfile, outputfile):
    f = open(outputfile, "w")
    pkts = rdpcap(inputfile)
    for pkt in pkts:
        if pkt.haslayer("IP"):
            if pkt.haslayer("TCP"):
                #print(pkt[TCP].payload)
                pkt.remove_payload()
    #           print (pkt)
            elif pkt.haslayer("UDP"):
                pkt.remove_payload()
    #           print(pkt)
            else:
                pkt.remove_payload()
    #           print (pkt)
        pkt_hex=bytes_hex(pkt)
    
    #   print(pkt_hex)
        pkt_bin = bin(int.from_bytes(pkt_hex, byteorder=sys.byteorder))
        pkt_final= pkt_bin[2:]
        #write to a file
        f.write(pkt_final)
        f.write("\n")
    f.close()
def main(argv):
    inputfile = ''
    outputfile = ''
#    print(f"Name of the script      : {sys.argv[0]=}")
#    print(f"Arguments of the script : {sys.argv[1:]=}")  
    try:
        opts, args = getopt.getopt(argv, "hi:o:" , ["ifile=","ofile="])
    except getopt.GetoptError:
        print ('pcap2bin.py -i <inputfile> -o <outputfile>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print ('pcap2bin.py -i <inputfile> -o <outputfile>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg
    print('Input:', inputfile)
    print('Output:', outputfile)
    pcap_to_bin(inputfile, outputfile)
if __name__ == "__main__":
    main(sys.argv[1:])
# Check the type of packet, there should only be data in TCP packets, UDP could also have them. Only have to check TCP before taking out payload, else do normal bin extract
