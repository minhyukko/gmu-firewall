import socket
import json
import selectors
import sys
import utils

"""
Networking Parameters.
"""
HOST = "127.0.0.1"
PORT = 49152

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

{
	"meta": {
				message_length: (int)    # bytes
				flow_lengths: tuple(int) # bytes
			}

	"data": [
				{
					"packets": (222,) array (str)
					"sip": (str)         
					"sport": (int)
				}
				.
				.
				.
				]	

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

Potential Issues:
	- novelty of using non-blocking sockets

"""

def terminate_connection(s, err=False):
	if err == True:
		print("connection broken, shutting down...")
	else:
		print("terminating connection...")
	
	s.close()

	quit()

def initiate_connection(s):

	print(f"connecting to {HOST}, {PORT}")
	s.connect((HOST, PORT))

	return s

def get_data(s):

	print("getting data...")

	# send flow signal
	print("    sending signal for data...")
	s.sendall(b"1")

	# read data
	print("    sending queries to server...")
	data = ""
	d = ""
	i = 0
	while True:
		d = s.recv(1024)
		print(f"		message {i} received")
		if not d:
			s.sendall(b"")
			terminate_connection(s)
		d = d.decode()
		data += d
		if "END" in d:
			data = data[:-3]
			break
		i += 1

	data = json.loads(data)

	return data

def process_flows(model, flows):
	"""
	Produces a set of predictions regarding the class of the flows.

	:param flows: (dict) -> the structure of the dictionary is identical to the one illustrated under
							NE-AE Message Protocol above but instead of packets being a (222,) string
							array (where each string is 222 characters long), it is now a (3, INPUT_DIM, INPUT_DIM)
							binary torch tensor.
							There must be 
	
	:return: (array(int)) -> the model inferences
	"""

	pckts = torch.stack([f["packets"] for f in flows], dim=0)
	tag_scores = model(pckts).numpy()
	inferences = [np.argmax(t_s) for t_s in tag_scores]
	
	return inferences

def transmit_rules(inferences):
	"""
	Transmit rules to the firewall according to model inferences.

	:param inferences: (array(int)) -> the model inferences

	:return:
	"""

	rules = []
	tags_to_rules = {0: "Normal",
				    1: "Infiltrating_Transfer", 
				    2: "Bruteforce_SSH", 
				    3: "DDoS",
				    4: "HTTP_DDoS"
				    }

	
	pass

def main():

	print("client running...")

	# create socket
	print("creating socket...")
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	# initiate connection
	s = initiate_connection(s)

	# process data
	model, _, _ = utils.load_ckpt("models/model.pt")
	model.eval()
	while True:
		data = get_data(s)
		data = utils.preprocess_rt(data)
		inferences = process_flows(model, data)
		transmit_rules(inferences)



if __name__ == "__main__":
	main()

	









