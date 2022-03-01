import sys
import numpy as np
import scapy.all as scapy
import socket
 
def main(argv):
    # define a socket before we start listening
    HOST = '127.0.0.1'
    PORT = 491
    socket=setup_socket(HOST, PORT)
    #create a global array to keep track of the 
    active_frame=np.empty([0,2])
    active_frame=scapy.sniff(iface="eth0",prn=add_pkt(active_frame,socket))
    return
def setup_socket(HOST, PORT):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST,PORT))
    except socket.error as err:
        print("Socket creation has failed with error %s"%(err))    
    return s

def add_ips(src,dst):
    src_arr=src.split(':')
    dst_arr=dst.split(':')
    for i in range(len(src_arr)):
        src_i= int(src_arr[i],16)
        dst_i= int(dst_arr[i],16)
        src_arr[i]=src_i+dst_i
    sum_string=''
    for i in range(len(src_arr)):
        sum_string= sum_string+str(src_arr[i])+':'
    return sum_string[:-1]

def add_pkt(a_frame,socket):
    a_frame=a_frame
    s=socket
    def get_pkt(pkt):
        nonlocal a_frame
        if pkt.haslayer("IP") and pkt.haslayer("TCP"): 
            src=pkt.src
            dst=pkt.dst
            pkt.remove_payload()
            pkt_hex=scapy.bytes_hex(pkt)
        else:
            #Log NON-TCP packet
            return
        add_ips(src,dst)
        #need to insert packet at the end of each block of ip pairs
        ip_hash = hash(add_ips(src,dst))
        # create some kind of hash function to order the packets byi
        a_frame=np.vstack((a_frame,[ip_hash,pkt_hex])) 
        if(np.shape(a_frame)[0]==222):#len(a_frame)):
            #Socket programming
            #Find some way to sort th:w
            #e dict
            #print("Original Frame:\n{}".format(a_frame))
            sorted_arr=a_frame[np.argsort(a_frame[:,0])]
            sorted_arr=np.delete(sorted_arr,0,axis=1)
            sorted_bytes=sorted_arr.tobytes()
            s.sendall(sorted_bytes)
            print("Sending Data to Server...")
            data = s.recv(sys.getsizeof(int()))
            print("Received Code {} from Server\n".format(data))
            #print("Sorted Frame:\n{}".format(sorted_arr))
            a_frame=np.empty([0,2])
            #send the sorted_arr to the socket
         
    #need to include an interrupt function to close the port when the program is ended
    return get_pkt
if __name__ == '__main__':
    main(sys.argv[1:])
