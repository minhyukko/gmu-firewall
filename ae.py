import socket
import json
import selectors
import sys
import utils
import torch

"""
Networking Parameters.
"""
HOST = "127.0.0.1"
PORT = 4912
SIZE_INT = 24

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
						"sip": None			   # IPv4 IP format
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
	

	print(f"setting up listener on {HOST}, {PORT}...")
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((HOST, PORT))
	s.listen()

	return s

def process_flow(model, flow):
	"""
	Produces a prediction for the passed flow.

	:param flow: (dict) -> the structure of the flow is illustrated under NE-AE Message Protocol above but
						   instead of packets being a (222,) string array (where each string is 222 characters long), 
						   it is now a (3, INPUT_DIM, INPUT_DIM) binary torch tensor
	
	:return: (array(int)) -> the model inference
	"""

	print("processing flow...")
	print(flow)
	quit()

	pckts = flow["flow"]["packets"]
	tag_scores = model(pckts).numpy()
	inference = np.argmax(tag_scores)

	return inference

def transmit_rules(inferences):
	"""
	Transmit rules to the firewall according to model inferences.

	:param inferences: (array(int)) -> the model inferences

	:return:
	"""

	rules = []
	tags_to_rules = {0: "Normal",
				    1: "Infiltrating_Transfer", 
				    2: "BruteForce",
				    }

	


def terminate_connection(s, conn=None, err=False):
	
	if err == True:
		print("connection broken, shutting down...")
	else:
		print("terminating connection...")
	
	s.close()
	if conn != None:
		conn.close()

	quit()


def main():

	print("server running...")

	# model, _, _ = utils.load_ckpt("models/model.pt")
	# model.eval()

	# create socket
	print("creating socket...")
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s = setup_listener(s)

	while True:

		# block to establish connection with NE
		conn, addr = s.accept()
		with conn:
			print(f"accepting connection to {addr}...")
			get_meta = True
			f = ""
			flow = ""
			recvd_size = 0
			# enter metadata / flow processing cycle with NE 
			while True:
				# get metadata (size)
				if get_meta == True:
					print("getting metadata...")
					size = conn.recv(1024)
					if not size:
						terminate_connection(s, conn, err=True)
					# confirm metadata reception
					s.sendall(b"0")
					get_meta = False
				else:
					print("getting flow...")
					# get flow
					f = s.recv(1024)
					if not f:
						terminate_connection(s)
					f = f.decode()
					flow += f
					if sys.getsizeof(flow) == size:
						print(f"flow receieved: {flow}")
						# confirm flow reception
						s.sendall(b"1")
						terminate_connection(s, conn)
						flow = json.loads(flow)
						inferences = process_flows(model, flow)
						transmit_rules(inferences)
						get_meta = True




if __name__ == "__main__":
	main()


