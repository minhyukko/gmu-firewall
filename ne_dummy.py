import socket
import json
import sys

# Constants
HOST = "127.0.0.1"
PORT = 4918
NORMAL_IDX = 0
ITRANSFER_IDX = 41

# get itransfer, normal packets from dataset
data_fpath = "../ae/data/test/test_0.json"
with open(data_fpath) as infile:
	data = json.load(infile)["test"]
packets_itransfer = data[ITRANSFER_IDX]["packets"]
packets_normal = data[NORMAL_IDX]["packets"]

# create dummy messages
msg_itransfer = {
					"packets": packets_itransfer,
					"sip": "283.1.3.1",
					"sport": 21,
					"dip": "127.0.0.1",
					"dport": 91
				}

msg_normal = {
				"packets": packets_normal,
				"sip": "452.1.2.1",
				"sport": 80,
				"dip": "127.0.0.1",
				"dport": 78
			}
messages = [msg_itransfer, msg_normal]


def initiate_connection(s):

	print(f"connecting to {HOST}, {PORT}")
	s.connect((HOST, PORT))

	return s

def terminate_connection(s, conn=None, err=False):
	
	if err == True:
		print("connection broken, shutting down...")
	else:
		print("terminating connection...")
	
	s.close()

	quit()

def display_message(msg):
	"""
	Displays message.
	"""

	# pckts = msg["packets"]
	sip = msg["sip"]
	dip = msg["dip"]
	sport = msg["sport"]
	dport = msg["dport"]
	print("Network Engine Message:")
	print("IP data:")
	print(f"	source ip: {sip}")
	print(f"	dest ip: {dip}")
	print(f"Port data:")
	print(f"	source port: {sport}")
	print(f"	dest port: {dport}")
	# print(f"packets: {pckts}")

def main():

	print("client running...")
	
	# connect to server
	print("creating socket...")
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	print(f"connecting to {(HOST, PORT)}...")
	s.connect((HOST, PORT))

	for i, msg in enumerate(messages):
		print(f"sending message {i}")
		msg_preproc = json.dumps(msg).encode("utf-8")
		msg_size = str(sys.getsizeof(msg_preproc)).encode("utf-8")
		
		# send length of message
		print(f"sending size of message: {msg_size}...")
		s.sendall(msg_size)
		
		# receive confirmation signal for metadata transmission / send flow
		print("waiting for confirmation signal...")
		conf = s.recv(1024)
		if not conf:
			terminate_connection(s, err=True)
		if conf.decode() == "0":
			print(f"confirmation receieved, sending message:\n{display_message(msg)}")
			s.sendall(msg_preproc)
			print("waiting for confirmation signal...")
			conf = s.recv(1024)
			# receieve confirmation signal for flow transmission
			if conf.decode() == "1":
				print(f"confirmation receieved, message {i} transmitted successfully!")
	

if __name__ == "__main__":
	main()






