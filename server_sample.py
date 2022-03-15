import sys
import numpy as np
import socket
import time
import threading
#threads = []

def AE(array):
    print("In AE")
    print("Data:{}".format(array))
    print("Type: ", type(array))


    #Min's Function Call
    return

def main(argv):
    HOST = "127.0.0.1"
    PORT = 491

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST,PORT))
        #s.listen()
        #conn,addr= s.accept()
        #with conn:
            #print("Connected by {}".format(addr))
        while True:
            curr_time=time.perf_counter()
            data,addr = s.recvfrom(7137)
            print("Connected by {}".format(addr))
            
            recv_time = time.perf_counter()
            #print("Data:{}".format(data2))
            #print("Type: ", type(data2))
            if not data:
                print("Data Not Received\nClosing...\n")
                conn.sendall(bytes(2))
                break

            data2 = np.frombuffer(data,dtype='S32', count=-1)
            print("Received Data:{} s".format(recv_time-curr_time))
            th = threading.Thread(target=AE, args=(data2,))
            #AE(data2)
            th.start()
            #conn.sendall(bytes(1))
    return


if __name__ == "__main__":
    main(sys.argv[1:])
