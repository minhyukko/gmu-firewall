import socket
import os
import sys



#Start each subprocess, listen for some message from that subprocess over port 999, start the next subprocess
# we should receive the message once the sockets have been created
# this socket should be the server, listening forany messages
def main (argv):
    server_address = "socket_fd/control.fd"
    log_file = "logs/control.log"
    timeout = 20
    interface = argv[0] 
    try:
        os.unlink(server_address)
    except OSError:
        if os.path.exists(server_address):
            raise
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
        s.bind(server_address)
        #set socket timeout to some value
        s.settimeout(timeout)
        os.system('sudo python3 fw.py &')
        try:
            msg = s.recv(32)
        except TimeoutError as err:
            print("Could not setup Firewall sockets")
            #end the fe process
            sys.exit(2)
        os.system("sudo -E python3 ae.py &")
        try:
            msg = s.recv(32)
        except TimeoutError as err:
            print("Could not setup Analytics Engine sockets")
            #end the ae process
            sys.exit(2)
        os.system("sudo python3 ne.py {} &".format(interface))
        

    pass

if __name__ == '__main__':
    
    try:
        arg1 = sys.argv[1]
    except IndexError:
        print("Usage: sudo stfu.py <interface>")
        sys.exit(1)

    main(sys.argv[1:])

