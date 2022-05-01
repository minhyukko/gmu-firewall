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
    delim = "}"
    conn, addr = s.accept()
    log("accepted connection to AE @ " + str(addr), do_print=True)
    with conn:
        msg_i = 0
        m_nxt = ""
        while True:
            get_meta = True
            m = ""
            msg = m_nxt
            swoops = 0
            # enter metadata / message processing cycle with NE 
            while True:
                if swoops == 0: log("attempting to receieve message " + str(msg_i) + "...", do_print=True)
                log("swoop " + str(swoops) + "...", do_print=True); swoops += 1
                # get message segment
                m = conn.recv(1024)
                # logging.info("segment of message receieved:\n{m}")
                if not m:
                    terminate_connection(s, conn, err=True)
                m = m.decode()
                m_curr = m
                # full message receieved
                if delim in m:
                    log("complete message received!", do_print=True)
                    delim_idx = m.find(delim)
                    # m may include parts of the next message
                    m_curr = m[:delim_idx+1]
                    m_nxt = ""
                    if delim_idx < len(m) - 1:
                        m_nxt = m[delim_idx+1:]
                    msg += m_curr
                    msg = json.loads(msg)
                    implement_rule(msg)
                    log("sending confirmation signal, onto the next message!", do_print=True)
                    conn.sendall(b"1")
                    msg_i += 1
                    break
                msg += m_curr

if __name__ == "__main__":
    main()
