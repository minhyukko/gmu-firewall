import sys
import numpy as np
import scapy.all as scapy
import socket
import gen_flows as gf

BUFF_SIZE = 1024

def main(argv):
    # define a socket before we start listening
    HOST = '127.0.0.1'
    PORT = 491
    server_address = 'socket_fd/uds_socket'
    
    
    #socket setup
    socket=setup_socket(server_address)
    #Add the Hashmap with the new socket
    hm = gf.HashMap(100, .75, 25, socket)
    scapy.ls('TCP')
    #create a global array to keep track of the 
    active_frame=np.empty([0,2])

    active_frame=scapy.sniff(iface="eth0",prn=add_pkt(hm,active_frame,socket,server_address))
    return
def setup_socket(server_address):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        print('Connecting to',server_address)
        s.connect(server_address)
    except socket.error as err:
        print("Socket creation has failed with error %s"%(err)) 
        sys.exit(1)
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

def add_pkt(hm,a_frame,socket,server_address):
    a_frame=a_frame
    hm=hm
    s=socket
    def get_pkt(pkt):
        nonlocal a_frame
        nonlocal hm
        global BUFF_SIZE
        
        if pkt.haslayer("IP") and pkt.haslayer("TCP"): 
            src=pkt.src
            dst=pkt.dst
            #pkt.remove_payload()
            pkt_hex=scapy.bytes_hex(pkt)
        else:
            #Log NON-TCP packet
            return
        '''
        add_ips(src,dst)
        #need to insert packet at the end of each block of ip pairs
        ip_hash = hash(add_ips(src,dst))
        # create some kind of hash function to order the packets by
        # Add 
        a_frame=np.vstack((a_frame,[ip_hash,scapy.bytes_hex(pkt)])) 
        '''
        #This is the integration portion
        #Create a new node if there is not a node for the src dst pair
        #The searching for whether or not a new flow is needed is handled in gen_flows (line 52)
        # create a new flow node to ostensibly
        hm = hm.add(pkt)

        # if fin is true get key for pkt
        '''
        if(np.shape(a_frame)[0]==BUFF_SIZE):
            # Sort the array by the hash of src+dst IP, then remove the hash
            sorted_arr=a_frame[np.argsort(a_frame[:,0])]
            # Remove the hash col 
            sorted_arr=np.delete(sorted_arr,0,axis=1)
            
            print(sorted_arr.dtype)
            sorted_bytes=sorted_arr.tobytes()
            arr_size = sys.getsizeof(sorted_bytes)
            s.sendall(bytes(str(arr_size),'utf8'))
            s.recv(sys.getsizeof(int()))
            print("Sending {} Bytes of Data to Server...".format(arr_size))
            s.sendall(sorted_bytes)
            print("Data Sent")
            a_frame=np.empty([0,2])
        '''
    #need to include an interrupt function to close the port when the program is ended
    return get_pkt
if __name__ == '__main__':
    main(sys.argv[1:])
