import socket
import os
import json
import selectors
import sys
import utils
import torch
import torch.nn as nn
import torchvision.models as models

"""
Questions:
- reliably measuring size of incoming data (sys.getsize() is overestimating)
    - should we just use delimiters
"""

"""
Networking Parameters.
"""
HOST = "127.0.0.1"
PORT = 4918
server_address = 'socket_fd/ne_ae.fd'

"""
Model device.
"""
device = "cuda" if torch.cuda.is_available() else "cpu"

"""
Model hyperparameters.
"""
torch.manual_seed(42)
INPUT_DIM = 224
BATCH_SIZE = 32

"""
Model device.
"""
device = "cuda" if torch.cuda.is_available() else "cpu"

"""
NE-AE Message Protocol:

message_length: n

{

    "flow":
            {
                "packets": (222,) array (str)
                "dip": (str)
                "dport": (int)
                "sip": (str)      
                "sport": (int)
            }   

}

AE-FW Message Protocol:

{
    "meta": {
                message_length: (int)    # bytes
                rule_lengths: tuple(int) # bytes
            }

    "rule_set": [
                    {
                        "action": (str),       # {b, p, d}
                        "target_type": (str),  # {sip, sport}
                        "target": (str/int),   # {0-9}*
                        "protocol": (str),     # {tcp, udp}
                        "sip": None            # IPv4 IP format
                    }
                    .
                    .
                    .
                ]
}

ALG:
    Let server_sock be the server socket and ne_sock and model_sock be ephemeral sockets communicating with the NE and the model, respectively
    Let buf be the server-side buffer, buf_limit be the maximum number of data to be stored in buf at once
    Create server_sock
    Establish connection with ne through ne_sock
    Repeatedly:
        if len(buf) > buf_limit:
            for i in range(len(buf) - buf_limit)
                flow = buf[i]
                transmit flow through model_sock # model will store these in its own buffer, if needed
        else:
            reconstruct a network flow from d being transmitted through ne_sock
                - recv loop to read in header
                - recv loop to read in network flow
            if model_sock.ready == True: # in more detail: if len(model_buf) < buf_limit or model is not busy
                transmit the flow through model_sock
            else:
                store the flow in buf

"""


def setup_listener(s):
    
    try:
        os.unlink(server_address)
    except OSError:
        if os.path.exsists(server_address):
            raise
    print(f"setting up listener on {HOST}, {PORT}...")
    s.bind(server_address)
    s.listen(1)

    return 

def process_pckts(model, pckts):
    """
    Produces a prediction for the passed packet array.
    
    :return: (array(int)) -> the model inference
    """

    print("processing packets...")

    # preprocess packets
    print("preprocessing to prepare packets for input to model...")
    pckts = utils.preprocess_rt(pckts)
    
    # perform inference
    print("performing inference...")
    with torch.no_grad():
        pckts = pckts.to(device)
        tag_scores = model(pckts[None, ...])
        inference = torch.argmax(tag_scores)

    return inference


def transmit_rule(fw_socket, msg, inference):
    """
    Transmit rules to the firewall according to model inferences.


    :param inferences: (array(int)) -> the model inferences

    :return:
    """


    # for now, firewall will always block source IP
    rule = {
                "action": "b",       # {b, p, d}
                "target_type": "sip",  # {sip, sport}
                "target": msg["sip"],  # {0-9}*
                "protocol": "tcp",     # {tcp, udp}
                "sip": None            # IPv4 IP format
            }

    rule_preproc = json.dumps(rule).encode("utf-8")
    rule_size = str(sys.getsizeof(rule_preproc)).encode("utf-8")

    # send size of rule
    print(f"sending size of rule: {rule_size}...")
    fw_socket.sendall(rule_size)
    
# receive confirmation signal for metadata transmission / send flow
    print("waiting for confirmation signal...")
    conf = fw_socket.recv(1024)
    if not conf:
        terminate_connection(fw_socket, err=True)
    if conf.decode() == "0":
        print(f"confirmation receieved, sending rule:\n{rule}")
        fw_socket.sendall(rule_preproc)
        conf = fw_socket.recv(1024)
        # receieve confirmation signal for flow transmission
        if conf.decode() == "1":
            print("confirmation receieved, rule transmitted successfully!")

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


def display_message(msg):
    """
    Displays message.
    """

    # pckts = msg["packets"]
    sip = msg["src"]
    dip = msg["dst"]
    sport = msg["sport"]
    dport = msg["dport"]
    print("Network Engine Message:")
    print("IP data:")
    print(f"    source ip: {sip}")
    print(f"    dest ip: {dip}")
    print(f"Port data:")
    print(f"    source port: {sport}")
    print(f"    dest port: {dport}")
    # print(f"packets: {pckts}")

def main():

    # only here temporarily
    ix_to_tags = {  0: "Normal",
                    1: "Infiltrating_Transfer",
                    2: "BruteForce"}

    print("server running...")

    print("setting up model...")
    num_classes = 3
    model = models.densenet121(pretrained=True)
    model.classifier = nn.Sequential(nn.Linear(in_features=1024, out_features=num_classes), nn.ReLU(), nn.Softmax(dim=1))
    model.to(device)
    model.eval()
    #setup socket to listen for client connections
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        setup_listener(s)
        # establish connection with NE (blocking call)
        conn, addr = s.accept()
        print(f"accepted connection to {addr}")
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
                            msg_size = int(str(msg_size, 'utf-8'))
                            # confirm metadata reception
                            print("send confirmation signal...")
                            conn.sendall(b"0")
                            get_meta = False
                        else:
                            print(f"swoop {swoops}...")
                            # get message segment
                            m = conn.recv(msg_size)
                            # print(f"segment of message receieved:\n{m}")
                            if not m:
                                terminate_connection(s)
                            m = m.decode()
                            msg += m
                            swoops += 1
                            # full message recieved
                            # if sys.getsizeof(msg) == msg_size:
                            if msg[-1] == "}":
                                print(f"complete message receieved!")
                                # display message
                                msg = json.loads(msg)
                                display_message(msg)
                                # process message
                                inference = process_pckts(model, msg["pkt"])
                                print(f"the packets were classified as {ix_to_tags[int(inference)]}")
                                # confirm message reception
                                print("sending confirmation signal, onto the next message!")
                                conn.sendall(b"1")
                                msg_i += 1
                                # allow variable reset
                                break


if __name__ == "__main__":
    main()















# def AE(array):
#     print("In AE")
#     print("Data:{}".format(array))
#     print("Type: ", type(array))


#     #Min's Function Call
#     return

# def main(argv):
    
#     server_address = "socket_fd/ne_ae.fd"
#     T_OUT= .00001

#     # Make sure the socket does not already exist
#     try:
#         os.unlink(server_address)
#     except OSError:
#         if os.path.exists(server_address):
#             raise

#     with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
#         print("Starting up Socket".format(server_address))
#         s.bind(server_address)
#         s.listen(1)
#         conn, addr= s.accept()
#         with conn :
#             print(f"Connection From {addr}")
#             while True: 
#                 #get the size of the data to be transmitted and look for the terminating character < >
#                 print("Receive Size...")
#                 bytes_size = conn.recv(1024)
#                 bytes_size = str(bytes_size, 'utf8')
#                 bytes_size = int(bytes_size)
#                 print("Received Size :{}".format(bytes_size))
#                 print("Send Ready Message for Data")
#                 conn.sendall(bytes(1))
#                 print("Receiving Data")
#                 data = conn.recv(bytes_size)
#                 print(data) 
#                 #data = np.frombuffer(data, dtype='S32')
#                 print("Data\n{}".format(sys.getsizeof(data)))
#                 #conn.sendall(bytes(1))
#     return


# if __name__ == "__main__":
#     main(sys.argv[1:])





