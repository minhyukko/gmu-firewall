import socket
import os 

HOST = "127.0.0.1"
PORT = 1492 

if os.path.exists("/tmp/socket_test.s"):
    os.remove("/tmp/socket_test.s")

server_address = './uds_socket'

try:
    os.unlink(server_address)
except OSError:
    if os.path.exists(server_address):
        raise

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(server_address)
#s.bind((socket.gethostname(), 1235))
#s.bind((socket.gethostname(), 1492))
s.listen(15)

while True:
    # now our endpoint knows about the OTHER endpoint.
    clientsocket, address = s.accept()
    print(f"Connection from {address} has been established.")
    data = clientsocket.recv(1024)
    if not data:
        break
    clientsocket.sendall(data)
"""
    try:
        clientsocket.send(bytes("192.164.3.12","utf-8"))
    except clientsocket.error as err:
        print("Clientsocket send function failed. Trying to connect...")
        clientsocket.connect((HOST, PORT))

    clientsocket.close()
"""
