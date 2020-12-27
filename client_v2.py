#!/usr/bin/env python3

import socket
from threading import Thread
import json


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 8880))

class RecieverThread(Thread):

    def __init__(self, client_conection):
        Thread.__init__(self, daemon=True)
        self.client_conection = client_conection

    def run(self):

        while  True:
            m = self.client_conection.recv(1024)
            if m != b"":
                message = json.loads(m.decode())
                print(f"\n[ {message['sender']} ] : {message['data']}\n[ {client_name} ] >> ",end='')

client_name = input("Input your name : ")
client_socket.send(client_name.encode())

reciever_name = input("Input the reciever_name : ")

reciever = RecieverThread( client_socket)
reciever.start()
reciever.isDaemon()

while  True:
    print(f"[ {client_name} ] >> ",end='')
    data_input = input()

    if data_input == "exit":
        client_socket.close()

        break

    if data_input != "":
        message =  {}
        message["sender"] = client_name
        message["receiver"] = reciever_name
        message["data"] = data_input

        data = json.dumps(message)

        client_socket.send(data.encode())
