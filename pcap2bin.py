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
def pcap_to_bin(inputfile, outputfolder):
    pkts = rdpcap(inputfile)
    line_length = 0;
    file_num=0
    image_arr =[][]
    i=0
    for pkt_i in pkts:
        if pkt_i.haslayer("IP"):
            if pkt_i.haslayer("TCP"):
                #print(pkt[TCP].payload)
                pkt_i.remove_payload()
    #           print (pkt)
            elif pkt_i.haslayer("UDP"):
                pkt_i.remove_payload()
    #           print(pkt)
            else:
                pkt_i.remove_payload()
    #           print (pkt)
        pkt_hex=bytes_hex(pkt_i)
    #   print(pkt_hex)
        pkt_bin = bin(int.from_bytes(pkt_hex, byteorder=sys.byteorder))
        pkt_final= pkt_bin[2:]

        #establich a line length
        if line_length ==0:
            line_length = len(pkt_final)
        #debug to check if all line lengths are the same
        #elif line_length != len(pkt_final):
        #   print('line lengths not equal')
       
        #add each bit one at a time to the array
        for bit_j in range(len(pkt_final)): 
            if pkt_final[bit_j] == 1:
                image_arr[i].append(0)
            elif pkt_final[bit_j] == 0:
                image_arr[i].append(255)
            else:
                print("NON BINARY ELEM")

        #increase line number
        i+=1
        #check if line number equals the length of the square packet
        if i > line_length:
            #if true, send array to be turned into an image and clear the array
            create_image(outputfolder, image_arr, file_num)
            #reset i
            image_arr = [][]
            i=0

        #else continue reading in lines
#if the number of lines is less than the line length pad the end of the image until the square is made
while i< linelength:
    filler_line = "0"* line_length
    image_arr[
    #if i< line length then add lines to pad the bottom of the array until there are enought lines to send the array to the image generation
def create_image(outputfolder, image_arr, file_num):
    # write an image to the file and number the file
    outputfile = outputfolder + "" + file_num
    cv2.imwrite(ouputfile, image_arr)
    file_num = 1+file_num
    return

def main(argv):
    inputfile = ''
    outputfolder = ''
#    print(f"Name of the script      : {sys.argv[0]=}")
#    print(f"Arguments of the script : {sys.argv[1:]=}")  
    try:
        opts, args = getopt.getopt(argv, "hi:o:" , ["ifile=","ofolder="])
    except getopt.GetoptError:
        print ('pcap2bin.py -i <pcap inputfile> -o <outputfolder>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print ('pcap2bin.py -i <pcap inputfile> -o <outputfolder>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofolder"):
            outputfolder = arg
    print('Input:', inputfile)
    print('Output:', outputfolder)
    pcap_to_bin(inputfile, outputfolder)
if __name__ == "__main__":
    main(sys.argv[1:])
# Check the type of packet, there should only be data in TCP packets, UDP could also have them. Only have to check TCP before taking out payload, else do normal bin extract
