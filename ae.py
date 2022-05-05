import socket
import os
import json
import sys
import utils
import logging
import torch
import torch.nn as nn
import torch.optim as optim
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
    "rule":
                    {
                        "action": (str),       # {b, p, d}
                        "target_type": (str),  # {sip, sport}
                        "target": (str/int),   # {0-9}*
                        "protocol": (str),     # {tcp, udp}
                        "sip": None            # IPv4 IP format
                    }
}
"""

def setup_logging(filename):

    logging.basicConfig(filename = filename,
                        filemode = 'w',
                        encoding = 'utf-8', 
                        level= logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def handler(signum, frame):
    logging.info("Closing the Network Engine")
    logging.shutdown()
    exit(1)


def setup_listener(s, socket_address):
    
    try:
        os.unlink(socket_address)
    except OSError:
        if os.path.exists(socket_address):
            raise
    
    logging.info("setting up listener on %s ...", socket_address)
    print(f"setting up listener on {socket_address} + ...")
    s.bind(socket_address)
    s.listen(1)

def setup_socket(socket_address):

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        logging.info("connecting to %s ...", socket_address)
        print(f"Connectig to {socket_address} ...")
        s.connect(socket_address)
        logging.info("connection established")
        print("connection established!")
    except socket.error as err:
        logging.error("socket creation has failed with error %s", err)
        print(f"Socket creation has failed with error {err}") 
        sys.exit(1)

    control_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    control_socket.sendto(b'2', 'socket_fd/control.fd')
    
    return s

def process_pckts(model, pckts):
    """
    Produces a prediction for the passed packet array.
    
    :return: (array(int)) -> the model inference
    """

    logging.info("processing packets...")
    print("processing packets...")

    # preprocess packets
    logging.info("preprocessing to prepare packets for input to model...")
    print("preprocessing to prepare packets for input to model...")
    pckts = utils.preprocess_rt(pckts)
    
    # perform inference
    logging.info("performing inference...")
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

    logging.info("transmitting rule...")
    print("transmitting rule...")
    
    # for now, firewall will always block source IP
    rule = {
                "action": "b",       # {b, p, d}
                "target_type": "src",  # {sip, sport}
                "target": msg["src"],  # {0-9}*
                "protocol": "tcp",     # {tcp, udp}
                "src": None            # IPv4 IP format
            }

    rule_preproc = json.dumps(rule).encode("utf-8")
    fw_socket.sendall(rule_preproc)
    conf = fw_socket.recv(1024)
    # receieve confirmation signal for flow transmission
    if conf.decode() == "1":
        logging.info("confirmation receieved, rule transmitted successfully!")
        print("confirmation receieved, rule transmitted successfully!")

def terminate_connection(s, conn=None, err=False):
    """
    Terminates connection.
    """

    if err == True:
        logging.info("connection broken, shutting down...")
        print("connection broken, shutting down...")
    else:
        logging.info("terminating connection...")
        print("terminating connection...")
    
    s.close()
    if conn != None:
        conn.close()
    sys.exit(1)


def display_message(msg):
    """
    Displays message.
    """

    # pckts = msg["packets"]
    sip = msg["src"]
    dip = msg["dst"]
    sport = msg["sport"]
    dport = msg["dport"]
    
    logging.info("Network Engine Message:")
    print("Network Engine Message:")
    
    logging.info("IP data:")
    print("IP data:")

    logging.info("    source ip: %s", sip)
    print(f"    source ip: {sip}")

    logging.info("    dest ip: %s", dip)
    print(f"    dest ip: {dip}")

    logging.info("Port data:")
    print(f"Port data:")

    logging.info("    source port: %d", sport)
    print(f"    source port: {sport}")

    logging.info("    dest port: %d", dport)
    print(f"    dest port: {dport}")

def main():

    # SIGINT signal handler saves log files before termination 
    signal.signal(signal.SIGINT, handler)

    # setup logging
    ae_log = "./logs/ae.log"
    setup_logging(ae_log)

    # for logging purposes
    ix_to_tags = {  0: "Normal",
                    1: "Infiltrating_Transfer",
                    2: "BruteForce"}

    logging.info("server running...")
    print("server running...")

    # set up model
    logging.info("setting up model...")
    print("setting up model...")
    num_classes = 3
    model = models.densenet121(pretrained=True)
    model.classifier = nn.Sequential(nn.Linear(in_features=1024, out_features=num_classes), nn.ReLU(), nn.Softmax(dim=1))
    optimizer = optim.Adam(model.parameters(), lr=0.01)
    model, _, _ = utils.load_ckpt("model.pt", model=model, optimizer=optimizer, device="cpu")
    model.to(device)
    model.eval()

    # set up firewall socket
    fe_sock = setup_socket(fe_address)
	
    delim = "}"
    # setup socket to listen for client connections
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as ne_sock:
        setup_listener(ne_sock, ne_address)
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
                    if swoops == 0:
                        logging.info("attempting to receieve message %d", msg_i) 
                        print(f"attempting to receieve message {msg_i}...")
                        logging.info("swoop %d", swoops)
                        print(f"swoop {swoops}...")
                        swoops += 1

                    # get message segment
                    m = conn.recv(1024)
                    if not m:
                        terminate_connection(ne_sock, conn, err=True)
                    m = m.decode()
                    m_curr = m
                    # full message receieved
                    if delim in m:
                        logging.info("complete message receieved!")
                    	print("complete message receieved!")
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
                        logging.info("the packets were classified as %s", ix_to_tags[int(inference)])
                    	print(f"the packets were classified as {ix_to_tags[int(inference)]}")
                    	# confirm message reception
                        logging.info("sending confirmation signal, onto the next message!")
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
