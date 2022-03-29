import socket

HOST = "127.0.0.1"
PORT = 1492 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s.bind((socket.gethostname(), 1235))
s.bind((socket.gethostname(), 1492))
s.listen(15)

while True:
    # now our endpoint knows about the OTHER endpoint.
    clientsocket, address = s.accept()
    print(f"Connection from {address} has been established.")

    try:
        clientsocket.send(bytes("192.164.3.12","utf-8"))
    except clientsocket.error as err:
        print("Clientsocket send function failed. Trying to connect...")
        clientsocket.connect((HOST, PORT))

    clientsocket.close()
