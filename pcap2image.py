import sys
import getopt
import cv2
import os
import numpy
from scapy.all import *
from scapy.utils import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP, UDP 

import inspect

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
    image_arr =[]
    i=0
    for pkt_i in pkts:
        if pkt_i.haslayer("IP"):
            if pkt_i.haslayer("TCP"):
                #print(pkt[TCP].payload)
                pkt_i.remove_payload()
                #print (pkt)
            elif pkt_i.haslayer("UDP"):
                pkt_i.remove_payload()
                #print(pkt)
            else:
                pkt_i.remove_payload()
                #print (pkt)
        #print(inspect.getsourcefile(bytes_hex))
        pkt_hex=bytes_hex(pkt_i)
        #print(pkt_hex)
        pkt_bin = bin(int.from_bytes(pkt_hex, byteorder=sys.byteorder))
        pkt_final= pkt_bin[2:]

        #establich a line length
        if line_length ==0:
            line_length = len(pkt_final)
            # line length is 222 rn

        image_arr = numpy.empty([line_length, line_length,3])

        #debug to check if all line lengths are the same
        #elif line_length != len(pkt_final):
        #   print('line lengths not equal')
    
        #add each bit one at a time to the array
        for bit_j in range(len(pkt_final)):
            #a one should be white, a zero black
            #print("i: {}\nj: {}\n".format(i,bit_j)) 
            if pkt_final[bit_j]=='1':
                for k in range(3):
                    image_arr[i][bit_j][k]=255
            elif pkt_final[bit_j] =='0':
                for k in range(3):
                    image_arr[i][bit_j][k]=0
            else:
                print("NON BINARY ELEM")

        #increase line number
        i+=1
        #check if line number equals the length of the square packet
        if i == line_length:
            #if true, send array to be turned into an image and clear the array
            file_num+=1
            create_image(outputfolder, image_arr, file_num)
            #reset i
            image_arr = []
            i=0
        #else continue reading in lines
    #if the number of lines is less than the line length pad the end of the image until the square is made
    if i<line_length:
        while i< line_length:
            for j in range(line_length):
                image_arr[i][j]=[0,0,0]
            i+=1
        file_num+=1
        create_image(outputfolder, image_arr, file_num)
    #if i< line length then add lines to pad the bottom of the array until there are enought lines to send the array to the image generation
    return

def create_image(outputfolder, image_arr, file_num):
    # write an image to the file and number the file
    image_arr = numpy.asarray(image_arr)
    outputfile = outputfolder + "_" +str(file_num)+".jpg"
    print(outputfile)
    saved_image = cv2.imwrite(outputfile, image_arr)
    return

def main(argv):
    inputfile = ''
    outputfolder = ''
#    print(f"Name of the script      : {sys.argv[0]=}")
#    print(f"Arguments of the script : {sys.argv[1:]=}")  
    try:
        opts, args = getopt.getopt(argv, "hi:o:" , ["ifile=","ofolder="])
    except getopt.GetoptError:
        print ('pcap2image.py -i <pcap inputfile> -o <outputfolder>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print ('pcap2image.py -i <pcap inputfile> -o <outputfolder>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofolder"):
            outputfolder = arg
    inputfile = os.path.abspath(os.getcwd())+"/"+inputfile    
    print('Input:', inputfile)
    print('Output:', outputfolder)
    os.mkdir(outputfolder)
    os.chdir(outputfolder)
    pcap_to_bin(inputfile, outputfolder)
    print("Complete")
if __name__ == "__main__":
    main(sys.argv[1:])
# Check the type of packet, there should only be data in TCP packets, UDP could also have them. Only have to check TCP before taking out payload, else do normal bin extract
