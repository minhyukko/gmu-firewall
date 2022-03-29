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
         
    else:
        print("Invalid Ip address")
        exit()


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((socket.gethostname(), 1492))
except socket.error as err:
    print("Socket creation failed %s" % (err))



full_msg = ''
while True:
    msg = s.recv(15)

    if len(msg) <= 0:
        break
    if not msg:
        try:
            s.connect((socket.gethostname(), 1235))
        except socket.error as err:
            print("Socket creation failed %s" % (err))
    full_msg += msg.decode("utf-8")

    check(full_msg)
    
    x = '{ "actions":"b", "target_type":"sip", "target":"192.168.13.15"}'
    y = json.loads(x)

    print(full_msg)
    print(y["target"])
    # os.system(full_msg) #sudo ufw deny from 203.0.113.100
    os.system("cal") #sudo ufw deny from 203.0.113.100

