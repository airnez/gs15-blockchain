#!/usr/bin/env python3


import socket
from threading import Thread
import json
import struct

from blockchain import Transaction, Blockchain

"""
    Alice <------>  Server <----->  Bob

    This serveur receieves messages from his client via sockets,
        and resend messages to the right client receiever

    > Client names must be "alice" and "bob", because they need
    a file named : "<alice/bob>_safe_512_prime_<number>" containing
    a 512 bits safe prime number

        : a different name will leads to find a safe prime, wich
            needs 5 mintutes of computation

    ========================      Usage  =======================

        : Run the serveur script in a terminal
        : Run in two differents terminals the client script
            : one with "alice" as client name and "bob" as receiever
            : one with "bob" as client name and "alice" as receiver

   ==============================================================




   TO DO


     : message server -> client pour print résultat
     X : print json serveur des transactions propre
    : requirements.txt

"""


class ServerThread(Thread):

    def __init__(self, client_conection, client_name):
        Thread.__init__(self, daemon=True)
        self.client_conection = client_conection
        self.client_name = client_name
        self.client_connected = True
        self.blockchain = None

    """
        Every message received by the server is printed
    """

    def print_message(self, message):

        print("\n=========================================================\n")
        print(f"from {message['sender']} ==>  to  ==>  {message['receiver']}\n")

        for key in message.keys():
            if key in ["p", "alpha", "h", "n", "e", "A", "x", "d", "public_key_to_check"]:
                print(f"\t{key} : {hex(message[key])}\n")
                continue

            if key == "signature":
                if type(message[key]) == list:
                    print(f"\tsignature\n\t\ts1 : {hex(message[key][0])}\n" +
                          f"\t\ts2 : {hex(message[key][1])}\n")
                continue

            if key == "transaction":
                m = message["transaction"]
                print("\ttransaction :")
                for k in m.keys():

                    if isinstance(m[k], dict):
                        print(f"\t\t{k} :")
                        for kk in m[k].keys():
                            try:
                                print(f"\t\t\t{kk} : {hex(m[k][kk])}")
                            except:
                                print(f"\t\t\t{kk} : {m[k][kk]}")
                        continue
                    try:
                        print(f"\t\t{k} : {hex(m[k])}")
                    except:
                        print(f"\t\t{k} : {m[k]}")
                continue

            else:
                print(f"\t{key} : {message[key]}")

    """
        Function runed in a thread, listen the client socket.
        A new thread is created at each new client connection
    """

    def run(self):
        while self.client_connected:
            self.check_blockchain_stored()
            # récupère la taille du message à lire
            message_length = self.client_conection.recv(4)
            if message_length != b"":
                message_length = struct.unpack(">L", message_length)[0]

                receieved_bytes = 0
                receieved_message = b""

                while receieved_bytes < message_length:
                    receieved_chunk = self.client_conection.recv(1024)
                    receieved_bytes = receieved_bytes + len(receieved_chunk)
                    receieved_message = receieved_message + receieved_chunk

                message = json.loads(receieved_message.decode())
                receiver = message["receiver"]

                self.print_message(message)

                if receiver == "server":
                    self.parse_message(message)
                else:
                    # envoi du message au destinataire
                    self.send_json_message(message, receiver)
                    """message_to_send = struct.pack(">L", message_length) + \
                        json.dumps(message).encode()
                    client_conections_dict[receiver].sendall(message_to_send)"""
    """
        Send a message to the client wich this thread is connected to
    """

    def send_json_message(self, message, receiver):
        json_message = json.dumps(message).encode()
        message_length = len(json_message)

        message_to_send = struct.pack(">L", message_length) + json_message
        client_conections_dict[receiver].sendall(message_to_send)

    """
        returns true if a blockchain is stored with name "gs15_blockchain" and loads it if true
    """

    def check_blockchain_stored(self):
        try:
            # if there is a file load the blockchain
            with open(f"gs15_blockchain", "r") as _:
                self.blockchain = Blockchain.load("gs15_blockchain")
                return True

        # if not : wait for first transaction signature type
        except FileNotFoundError:
            return False

    def parse_message(self, message):
        if message["message_type"] == "exit_message":
            print("\n=========================================================\n")
            print(f"\n\n\t\t *** {self.client_name} disconnected ****\n")
            del client_conections_dict[self.client_name]
            self.client_conection.close()
            self.client_connected = False

        if message["message_type"] == "transaction_message":
            new_transaction = Transaction.deserialize(message["transaction"])
            if self.blockchain is None:
                if not self.check_blockchain_stored():
                    self.blockchain = Blockchain(new_transaction.signature["signature_type"])
            self.blockchain.add_transaction(transaction=new_transaction)
            self.blockchain.save("gs15_blockchain")

        if message["message_type"] == "verification_message":
            self.check_blockchain_stored()
            response = {"message_type": "server_response"}
            response["receiver"] = self.client_name

            # print("\n=========================================================\n")
            if self.blockchain is not None:
                response["content"] = f"Blockchain verification status: {self.blockchain.verify()}\n"
            else:
                response["content"] = "No blockchain to verify !"
            self.send_json_message(response, self.client_name)

        if message["message_type"] == "balance_message":
            self.check_blockchain_stored()
            response = {"message_type": "server_response"}
            response["receiver"] = self.client_name
            # print("\n=========================================================\n")
            if self.blockchain is not None:
                response["content"] = f"Balance for {message['sender']} : " +\
                    f"{self.blockchain.get_account_balance(message['public_key_to_check'])}"
            else:
                response["content"] = "No blockchain to verify !"
            self.send_json_message(response, self.client_name)


if __name__ == '__main__':

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind(("", 8880))
    server_socket.listen(2)

    # dictionnary that maps the client name to his socket reference
    client_conections_dict = {}

    while True:
        print("waiting for new client ...\n")
        client_conection, connection_data = server_socket.accept()
        client_name = b""

        while client_name == b"":
            client_name = client_conection.recv(1024)

        client_name = client_name.decode()
        # put the client name and socket reference in the dict
        client_conections_dict[client_name] = client_conection
        # start a new thread that listens to this new socket
        newClientThread = ServerThread(client_conection, client_name)
        newClientThread.start()
        print(f" {client_name} is now connected\n")
