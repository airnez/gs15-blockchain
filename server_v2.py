#!/usr/bin/env python3


import socket

import time
from threading import Thread
import sys
import json


class ClientThread(Thread):

    def __init__(self, client_conection, client_name):
        Thread.__init__(self, daemon=True)
        self.client_conection = client_conection
        self.client_name = client_name

    def run(self):

        while  True:
            m = self.client_conection.recv(1024)
            if m != b"":
                #print(f"{self.client_name} sent : {m.decode()}")

                message = json.loads(m.decode())
                client_conections_dict[message["receiver"]].send(json.dumps(message).encode())

            if m == b"exit":
                del client_conections_dict[self.name]
                server_socket.close()


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind(("", 8880))

server_socket.listen(2)

client_conections_dict = {}

print("phase init connection")

while True:
    print("waiting for new client")
    client_conection, connection_data = server_socket.accept()
    client_name = b""

    while  client_name == b"":
        client_name = client_conection.recv(1024)

    client_name = client_name.decode()
    print(client_name, " recived")

    client_conections_dict[client_name] = client_conection

    newClientThread = ClientThread(client_conection, client_name )

    newClientThread.start()
    print("new client connected")
