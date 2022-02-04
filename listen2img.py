import sys
import os
import shutil
import getopt

import cv2
import numpy

from scapy.all import *
from scapy.utils import rdpcap, wrpcap
from scapy.layers.inet import IP,TCP,UDP


#222 is the line length of the packet after the payload has been removed
g_img_arr = numpy.empty([222,222,3])
g_row = 0
g_file_num =0

#from here we create the array to be made later into an image by adding packets one at a time
def add_pkt(pkt, img_arr=g_img_arr, row = g_row):
    global g_row 
    global g_img_arr
    if pkt.haslayer("IP") and pkt.haslayer("TCP"):
        pkt.remove_payload()
    else:
        return
    pkt_hex=bytes_hex(pkt)
    pkt_bin = bin(int.from_bytes(pkt_hex,byteorder=sys.byteorder))
    pkt_final=pkt_bin[2:]
    for bit in range(222):
        if pkt_final[bit]=='1':
            for color in range(3):
                g_img_arr[g_row][bit][color]=225
        elif pkt_final[bit]=='0':
            for color in range(3):
                g_img_arr[g_row][bit][color]=0
        else:
            print("NON BINARY ELEMENT")
    g_row+=1

    if g_row ==222:
        create_image(g_img_arr)
        g_img_arr = numpy.empty([222,222,3])
        g_row = 0
#
def create_image(img_arr):
    global g_file_num
    temp_img_arr = numpy.asarray(img_arr)
    outputfile = os.getcwd()+"/"+str(g_file_num)+".jpg"
    g_file_num+=1
    print(outputfile)
    saved_image = cv2.imwrite(outputfile,temp_img_arr)
    return
    
    
#create the file to store the temporary images (and other outputs)
def setup():
   outputfolder = "temp_image_folder"
   for file_name in os.listdir():
       if file_name == outputfolder:
           shutil.rmtree(outputfolder)
   os.mkdir(outputfolder)
   os.chdir(outputfolder)
   print(os.getcwd())

#from here we need to listen for all of the packets using the sniff method
def main(argv):
    setup()
    sniff(count =500, iface = "eth0",prn=add_pkt)

if __name__ =="__main__":
    main(sys.argv[1:])
