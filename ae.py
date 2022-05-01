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
TODO:
    - upload model.pt to Github
    - set ckpt_fname
"""

"""
Networking Parameters.
"""
ne_address = "socket_fd/ne_ae.fd"
fe_address = "socket_fd/ae_fe.fd"

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
        os.unlink(ne_address)
    except OSError:
        if os.path.exists(ne_address):
            raise
    
    print(f"setting up listener on " + ne_address)
    s.bind(ne_address)
    s.listen(1)

def setup_socket():

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        print('Connecting to {}'.format(fe_address))
        print('connected')
        s.connect(fe_address)
    except socket.error as err:
        print("Socket creation has failed with error %s"%(err)) 
        sys.exit(1)
    
    return s

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

    # set up model
    print("setting up model...")
    # model, _, _ = load_ckpt(ckpt_fname, model=None, optimizer=None):
    # model.to(device)
    # model.eval()

    num_classes = 3
    model = models.densenet121(pretrained=True)
    model.classifier = nn.Sequential(nn.Linear(in_features=1024, out_features=num_classes), nn.ReLU(), nn.Softmax(dim=1))
    model.to(device)
    model.eval()

    # set up firewall socket
    fe_sock = setup_socket(server_address)
	
    delim = "}"
    # setup socket to listen for client connections
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as ne_sock:
        setup_listener(ne_sock)
        # establish connection with NE (blocking call)
        conn, addr = ne_sock.accept()
        print(f"accepted connection to {addr}")
        with conn:
            msg_i = 0
            m_nxt = ""
            while True:
                m = ""
                msg = m_nxt
                swoops = 0
                # enter message processing cycle with NE 
                while True:
                    if swoops == 0: print(f"attempting to receieve message {msg_i}...")
                    print(f"swoop {swoops}..."); swoops += 1
                    # get message segment
                    m = conn.recv(1024)
                    # print(f"segment of message receieved:\n{m}")
                    if not m:
                        terminate_connection(s)
                    m = m.decode()
                    m_curr = m
                    # full message receieved
                    if delim in m:
                    	print(f"complete message receieved!")
                    	delim_idx = m.find("}")
                    	# m may include parts of the next message
                    	m_curr = m[:delim_idx+1]
                    	m_nxt = ""
                    	if delim_idx < len(m) - 1:
                    		m_nxt = m[delim_idx+1:]
                    	msg += m_curr
                    	msg = json.loads(msg)
                    	display_message(msg)
                    	# perform inference
                    	inference = process_pckts(model, msg["pkt"])
                    	print(f"the packets were classified as {ix_to_tags[int(inference)]}")
                    	# confirm message reception
                    	print("sending confirmation signal, onto the next message!")
                    	conn.sendall(b"1")
			# transmit rule
                    	transmit_rule(fe_sock, msg, inference)
                    	msg_i += 1
                    	# allow variable reset
                    	break
                    msg += m_curr
    
    fw_sock.close()


if __name__ == "__main__":
    main()
