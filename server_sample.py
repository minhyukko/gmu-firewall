import sys
import numpy as np
import socket
import time

def main(argv):
    HOST = "127.0.0.1"
    PORT = 491

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST,PORT))
        s.listen()
        conn,addr= s.accept()
        with conn:
            curr_time=time.perf_counter()
            print("Connected by {}".format(addr))
            while True:
                data = conn.recv(7224)
                recv_time = time.perf_counter()

                if not data:
                    print("Data Not Received\nClosing...\n")
                    conn.sendall(bytes(2))
                    break
                print("Received Data:{} s".format(recv_time-curr_time))

                conn.sendall(bytes(1))
    return


if __name__ == "__main__":
    main(sys.argv[1:])
