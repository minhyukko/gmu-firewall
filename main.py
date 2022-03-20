# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import multiprocessing
import os
import socket
import json
import sys

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


def print_cube(num):  # From the server
    """
    function to print cube of given num
    """
    #How will we receive data? In a txt file?
    HOST = "127.0.0.1"
    PORT = 492

    if os.path.exists("/tmp/socket_test.s"):
        os.remove("/tmp/socket_test.s")

    socket = setup_socket(HOST, PORT)

    server_address = './uds_socket'

    try:
        os.unlink(server_address)
    except OSError:
        if os.path.exists(server_address):
            raise

    socket.bind(server_address)

    # Listen for incoming connections
    socket.listen(1)

    while True:
        # Wait for a connection

        # print >> sys.stderr, 'waiting for a connection'
        # connection, client_address = socket.accept()
        # try:
        #     print >> sys.stderr, 'connection from', client_address
        #
        #     # Receive the data in small chunks and retransmit it
        #     while True:
        #         data = connection.recv(16)
        #         print >> sys.stderr, 'received "%s"' % data
        #         if data:
        #             print >> sys.stderr, 'sending data back to the client'
        #             connection.sendall(data)
        #         else:
        #             print >> sys.stderr, 'no more data from', client_address
        #             break

        conn, addr = server.accept()
        datagram = conn.recv(1024)
        if datagram:
            tokens = datagram.strip().split()
            if tokens[0].lower() == "post":
                flist.append(tokens[1])
                conn.send(len(tokens) + "")
            elif tokens[0].lower() == "get":
                conn.send(tokens.popleft())
            else:
                conn.send("-1")
        conn.close()

        # finally:
        #     # Clean up the connection
        #     connection.close()

    x = '{ "action":"b", "target_type":"sip", "target":"192.168.13.14", "protocol":"tcp", "sip":"None"}'
    y = json.loads(x)

    str = "ufw "
    if y["action"] == "b":
        str = str + "deny from " + y["target"]
    print(str)
    os.system('dir') # write the UFW command to the command line

    # print("Cube: {}".format(num * num * num))


def print_square(num): # From the client
    """
    function to print square of given num
    """

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = './uds_socket'
    print('connecting to %s' % server_address, file=sys.stderr)
    try:
        sock.connect(server_address)
    except socket.error as err:
        print("Socket creation failed %s" % (err))

    try:
        # Send data
        message = 'This is the message.  It will be repeated.'
        print('sending "%s"' % message, file=sys.stderr)
        sock.sendall(bytes(message, 'iso_8859_1'))

        amount_received = 0
        amount_expected = len(message)

        while amount_received < amount_expected:
            data = sock.recv(16)
            amount_received += len(data)
            print('received "%s"' % data, file=sys.stderr)

    finally:
        print('closing socket', file=sys.stderr)
        sock.close()

    print("Square: {}".format(num * num))

def setup_socket(HOST, PORT):
    try:
        # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # s.bind(HOST,PORT)
        # s.listen()
        # conn, address = s.accept() # conn - data, address - what is connecting to me
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        # socket.AF_UNIX
        server_address = './uds_socket'
        print('connecting to %s' % server_address, file=sys.stderr)
        
        s.connect(server_address)

    except socket.error as err:
        print("Socket creation failed %s"%(err))
        sys.exit(1)
    return s

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # creating processes
    while (1):
        p1 = multiprocessing.Process(target=print_square, args=(10,))
        p2 = multiprocessing.Process(target=print_cube, args=(10,))

        # starting process 1
        p1.start()
        # starting process 2
        p2.start()

        # wait until process 1 is finished
        p1.join()
        # wait until process 2 is finished
        p2.join()

        # both processes finished
        print("Done!")
        print_hi('PyCharm')


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
