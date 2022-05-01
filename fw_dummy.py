import socket
import os
import re 
import json 
import signal
import logging

HOST = "127.0.0.1"
PORT = 4913
regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

def check_ip(Ip):
    """
    Ensures the passed IP address is valid.
    """
    if(re.search(regex, Ip)):
        log("Valid Ip address")
        return True     
    else:
        log("Invalid Ip address")
        return False

    pass

def terminate_connection(s, conn=None, err=False):
    """
    Terminates connection.
    """

    if err == True:
        log("connection broken, shutting down...", do_print=True)
    else:
        log("terminating connection...", do_print=True)
    
    s.close()
    if conn != None:
        conn.close()

    quit()

def setup_listener():
    """
    Sets up a listening socket
    """
    server_address = './uds_socket'

    try:
        os.unlink(server_address)
    except OSError:
        if os.path.exists(server_address):
            raise

    log("setting up listener on " + str(HOST) + ", " + str(PORT) + "...", do_print=True)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(server_address)
    s.listen()

    return s

def implement_rule(msg):
    """
    Implements rule.
    
    msg = {'action': 'b', ...}
    """

    log("implementing rule...", do_print=True)
    log(msg["target"])
    if check_ip(msg["target"]):
    	log("sudo ufw deny from " + msg["target"], do_print=True)
    	os.system("sudo ufw deny from " + msg["target"])
    
def setup_logging(filename):
    logging.basicConfig(filename = filename,
                        filemode = 'w',
                        encoding = 'utf-8', 
                        level= logging.DEBUG,
                        format='%(name)s - %(levelname)s - %(message)s')

def handler(signum, frame):
    logging.info("Closing the Network Engine")
    logging.shutdown()
    exit(1)

def log(info, do_print=False):
    logging.info(info)
    if do_print == True:
        print(info)

def main():

    if os.path.exists("/tmp/socket_test.s"):
        os.remove("/tmp/socket_test.s")
        
    signal.signal(signal.SIGINT, handler)
    
    #setup logging
    fw_log =  './logs/fw.log'
    setup_logging(fw_log)
   
    s = setup_listener()
    # establish connection with AE (blocking call)
    conn, addr = s.accept()
    log("accepted connection to AE @ " + str(addr), do_print=True)
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
                    log("attempting to receieve message " + str(msg_i) + "...", do_print=True)
                # get metadata (size)
                if get_meta == True:
                    log("getting metadata...", do_print=True)
                    msg_size = conn.recv(1024)
                    logging.info("metadata receieved: message size={msg_size}")
                    if not msg_size:
                        terminate_connection(s, conn, err=True)
                    # confirm metadata reception
                    logging.info("send confirmation signal...")
                    conn.sendall(b"0")
                    get_meta = False
                else:
                    logging.info("swoop {swoops}...")
                    # get message segment
                    m = conn.recv(1024)
                    # logging.info("segment of message receieved:\n{m}")
                    if not m:
                        terminate_connection(s, conn, err=True)
                    m = m.decode()
                    msg += m
                    swoops += 1
                    if msg[-1] == "}":
                        logging.info("complete message receieved!")
                        # display message
                        msg = json.loads(msg)
                        logging.info(msg)
                        # implement the rule encoded in the message
                        implement_rule(msg)
                        # confirm message reception
                        logging.info("sending confirmation signal, onto the next message!")
                        conn.sendall(b"1")
                        msg_i += 1
                        # allow variable reset
                        break

if __name__ == "__main__":
    main()
