import socket
import os
import re 
import json 

regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
HOST = "127.0.0.1"
PORT = 1492

def check(Ip):
 
    # pass the regular expression
    # and the string in search() method
    if(re.search(regex, Ip)):
        print("Valid Ip address")
        return True     
    else:
        print("Invalid Ip address")
        return False

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
#s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_address = './uds_socket'
try:
    s.connect(server_address)
    #s.connect((socket.gethostname(), 1492))
    #conn, add = s.connect((socket.gethostname(), 1492))
except socket.error as err:
    print("Socket creation failed %s" % (err))

#s.bind((socket.gethostname(), 1492))
#s.listen()
#conn, addr = s.accept()
full_msg = ''
while True:
    #s.connect((socket.gethostname(), 1492))
    message = ('192.168.13.14')
    encoded = message.encode('utf-8')
    s.sendall(encoded)
    msg = s.recv(1024)
    #msg = conn.recv(1024)
    print("Here: ")
    #print(msg.decode())

    if len(msg) <= 0:
        break
    if not msg:
        try:
            s.connect((socket.gethostname(), 1235))
        except socket.error as err:
            print("Socket creation failed %s" % (err))
    full_msg += msg.decode("utf-8")

    valid = check(full_msg)
    if not valid:
        continue

    x = '{ "actions":"b", "target_type":"sip", "target":"192.168.13.15"}'
    y = json.loads(x)

    print(full_msg)
    print(y["target"])
    # os.system(full_msg) #sudo ufw deny from 203.0.113.100
    os.system("lscpu") #sudo ufw deny from 203.0.113.100

