# Network listener
# Script sends incoming network traffic to a set of flows and  
import sys
import numpy as np
import scapy.all as scapy
import socket
import gen_flows as gf
import logging
import os
import signal

def main(argv):
    #setup simple signal handler
    signal.signal(signal.SIGINT, handler)


    #setup logging
    ne_log =  './logs/ne.log'
    setup_logging(ne_log)

    # define a socket before we start listening
    server_address = 'socket_fd/ne_ae.fd' 
    socket=setup_socket(server_address)
    
    #Add the Hashmap with the new socket
    hm_log = './logs/gen_flows.log'
    hm = gf.HashMap(100, .75, 25, socket, hm_log)   
    active_frame=scapy.sniff(iface="eth0",prn=add_pkt(hm,socket,server_address))
    return

def setup_logging(filename):
    
    #logger = logging.getLogger()
    #logger.setLevel(logging.INFO)
    #formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')

    #file_handler = logging.FileHandler(filename)
    #file_handler.setFormatter(formatter)
    logging.basicConfig(filename = filename,
                        filemode = 'w',
                        encoding = 'utf-8', 
                        level= logging.DEBUG,
                        format='%(name)s - %(levelname)s - %(message)s')

def setup_socket(server_address):
    '''
    #make sure the socket file descriptor doesn't already exist
    try:
        os.unlink(server_address)
    except OSError:
        if os.path.exists(server_address):
            raise
    #Create the server file dexcriptor 
    try:
        with open(server_address,'w') as f:
            f.write('')
    except FileNotFoundError:
        logging.error("The socket_fd directory doesn't exist")
    '''

    #create the connection to the socket
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        logging.info('Connecting to {}'.format(server_address))
        s.connect(server_address)
    except socket.error as err:
        logging.error("Socket creation has failed with error %s"%(err)) 
        sys.exit(1)
    return s

def handler(signum, frame):
    logging.info("Closing the Network Engine")
    logging.shutdown()
    exit(1)

def add_pkt(hm,socket,server_address):
    hm=hm
    s=socket
    def get_pkt(pkt):
        nonlocal hm
        global BUFF_SIZE
        
        if pkt.haslayer("IP") and pkt.haslayer("TCP"): 
            src=pkt.src
            dst=pkt.dst
            pkt_hex=scapy.bytes_hex(pkt)
        else:
            #Log NON-TCP packet
            return
        #Add packet to hm, leave the decision making to the gen_flows.py
        hm = hm.add(pkt)
        #need to include an interrupt function to close the port when the program is ended
    return get_pkt
if __name__ == '__main__':
    main(sys.argv[1:])
