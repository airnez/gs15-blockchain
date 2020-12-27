#!/usr/bin/env python3


import socket

import time
from threading import Thread
import json
import struct


"""
    Alice ------  Server  ----- Bob

    Le serveur sert d'intermédiaire, reçoit et rénvoie tous
        les messages au bon destinataire

    > Les clients doivent s'appeller "alice" et "bob",
     car il leur faut leur fichier "alice_safe_512_prime_1" etc

     (on peut pas accepter d'autre clients, sinon il leur faudrait leurs
     fichiers de clés)

      de plus, les  clés de signatures sont stockées que pour un unique
        destinataire, garde pas plus en memoire (possible de le faire mais flemme)

    ========================      Usage  =======================


        : lancer le serveur
        : lancer dans 2 fois le script client dans des terminaux  différents

   ==============================================================

"""

class ServerThread(Thread):

    def __init__(self, client_conection, client_name):
        Thread.__init__(self, daemon=True)
        self.client_conection = client_conection
        self.client_name = client_name

    """
        Print les messages qui passent par le serveur
    """
    def print_message(self, message):

        print(f"from {message['sender']} ==>  to  ==>  {message['receiver']}\n")

        for key in message.keys():

            if key in ["p", "alpha", "h", "n", "e", "A", "x", "d"]:
                print(f"\t{key} : {hex(message[key])}\n")
                continue

            if key == "signature":
                if type(message[key]) == list:
                    print(f"\tsignature\n\t\ts1 : {hex(message[key][0])}\n"+\
                            f"\t\ts2 : {hex(message[key][1])}\n")
                continue

            else:
                print(f"\t{key} : {message[key]}")
        print("\n=========================================================\n")

    """
        Fonction dans un thread qui écoute un socket
    """
    def run(self):

        while  True:
            # récupère la taille du message à lire
            message_length = self.client_conection.recv(4)

            if message_length != b"":

                message_length = struct.unpack(">L", message_length)[0]

                recieved_bytes = 0
                recieved_message = b""

                while  recieved_bytes < message_length:

                    recieved_chunk =  self.client_conection.recv(1024)
                    recieved_bytes = recieved_bytes + len(recieved_chunk)

                    recieved_message = recieved_message + recieved_chunk

                message = json.loads(recieved_message.decode())
                receiver = message["receiver"]

                self.print_message(message)
                #envoi du message au destinataire
                message_to_send = struct.pack(">L", message_length) + json.dumps(message).encode()

                client_conections_dict[ receiver ].sendall( message_to_send )

                if message["message_type"] == "data":
                    if message["data"] == "exit":
                        del client_conections_dict[self.client_name]
                        server_socket.close()

if __name__ == '__main__':

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind(("", 8880))

    server_socket.listen(2)

    client_conections_dict = {}

    while True:
        print("waiting for new client ...\n")
        client_conection, connection_data = server_socket.accept()
        client_name = b""

        while  client_name == b"":
            client_name = client_conection.recv(1024)

        client_name = client_name.decode()
        # ajout du socket client dans la liste
        client_conections_dict[client_name] = client_conection
        # nouveau thread d'écoute du socket client
        newClientThread = ServerThread(client_conection, client_name )

        newClientThread.start()
        print(f" {client_name} is now connected\n")
