import socket
import os
import re 
import json 

HOST = "127.0.0.1"
PORT = 4919

def check_ip(ip):
    """
    Ensures the passed IP address is valid.
    """

    pass

def terminate_connection(s, conn=None, err=False):
    """
    Terminates connection.
    """

    if err == True:
        print("connection broken, shutting down...")
    else:
        print("terminating connection...")
    
    s.close()
    if conn != None:
        conn.close()

    quit()

def setup_listener():
    """
    Sets up a listening socket
    """

    print(f"setting up listener on {HOST}, {PORT}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()

    return s

def implement_rule(msg):
    """
    Implements rule.
    """

    print("implementing rule...")

    pass

def main():
   
    s = setup_listener()
    # establish connection with AE (blocking call)
    conn, addr = s.accept()
    print(f"accepted connection to AE @ {addr}")
    with conn:
        msg_i = 0
        while True:
            get_meta = True
            m = ""
            msg = ""
            recvd_size = 0
            msg_size = 0
            swoops = 0
            # enter metadata / message processing cycle with NE 
            while True:
                if swoops == 0:
                    print(f"attempting to receieve message {msg_i}...")
                # get metadata (size)
                if get_meta == True:
                    print("getting metadata...")
                    msg_size = conn.recv(1024)
                    print(f"metadata receieved: message size={msg_size}")
                    if not msg_size:
                        terminate_connection(s, conn, err=True)
                    # confirm metadata reception
                    print("send confirmation signal...")
                    conn.sendall(b"0")
                    get_meta = False
                else:
                    print(f"swoop {swoops}...")
                    # get message segment
                    m = conn.recv(1024)
                    # print(f"segment of message receieved:\n{m}")
                    if not m:
                        terminate_connection(s, conn, err=True)
                    m = m.decode()
                    msg += m
                    swoops += 1
                    # full message recieved
                    # if sys.getsizeof(msg) == msg_size:
                    if msg[-1] == "}":
                        print(f"complete message receieved!")
                        # display message
                        msg = json.loads(msg)
                        print(msg)
                        # implement the rule encoded in the message
                        implement_rule(msg)
                        # confirm message reception
                        print("sending confirmation signal, onto the next message!")
                        conn.sendall(b"1")
                        msg_i += 1
                        # allow variable reset
                        break

if __name__ == "__main__":
    main()