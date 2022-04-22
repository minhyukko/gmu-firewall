import sys
import numpy as np
import socket
import time
import threading
import os
#threads = []

def AE(array):
    print("In AE")
    print("Data:{}".format(array))
    print("Type: ", type(array))


    #Min's Function Call
    return

def main(argv):
  
    log_file = 'logs/ae.log'   
    server_address = 'socket_fd/ne_ae.fd'
    T_OUT= .00001
#    setup_logging(log_file)
    # Make sure the socket does not already exist
    try:
        os.unlink(server_address)
    except OSError:
        if os.path.exists(server_address):
            raise

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        print("Starting up Socket".format(server_address))
        s.bind(server_address)
        #The parameter to listen spcifies the number of unaccepted connections that the system will allow before refusing new connecitons. When empty it is something resoun
        s.listen(1)
        conn, addr= s.accept()
        with conn :
            print(f"Connection From {addr}")
            while True: 
                #get the size of the data to be transmitted and look for the terminating character < >
                bytes_size = conn.recv(1024)
                bytes_size = str(bytes_size, 'utf8')
                bytes_size = int(bytes_size)
#                logging.info("Received Data Size: {}".format(bytes_size))
                #print("Send Ready Message for Data")
                conn.sendall(bytes(1))
                #print("Receiving Data")
                data = conn.recv(bytes_size)
                #print(data) 
                #data = np.frombuffer(data, dtype='S32')
 #               logging.info("Data\n{}".format(sys.getsizeof(data)))
                #conn.sendall(bytes(1))
    return
#def setup_logging(filename):
#    try:
#        with open(filename,'w') as f:
#            f.write('Server Sample Log')
#    except FileNotFoundError:
#        logging.error("The socket_fd directory doesn't exist")

if __name__ == "__main__":
    main(sys.argv[1:])
