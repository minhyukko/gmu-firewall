import socket
import json

HOST = "127.0.0.1"
PORT = 65410

packets = ["0"*222]*222
data = {
	 		"flows": [
	 					{
	 						"packets": packets,
	 						"sip": "452.1.2.1",
	 						"sport": 80
	 					},
	 						
	 					{
	 						"packets": packets,
	 						"sip": "971.0.0.1",
	 						"sport": 92
	 					 }
	 				  ]
	    }
data = json.dumps(data) + "END"


def setup_listener(s):
	

	print(f"setting up listener on {HOST}, {PORT}")
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind((HOST, PORT))
	s.listen()

	return s

def service_connection(conn, addr):

	with conn:
		print(f"accepting connection to {addr}")
		while True:
			client_data = conn.recv(1024)
			if not client_data:
				terminate_connection(s, conn)
			elif client_data == b"1":
				conn.sendall(bytes(data, encoding="utf-8"))

	return conn

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

	# create socket
	print("creating socket...")
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	s = setup_listener(s)

	# establish connection
	conn, addr = s.accept()
	conn = service_connection(conn, addr)

	terminate_connection(s, conn)









