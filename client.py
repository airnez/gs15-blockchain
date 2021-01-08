#!/usr/bin/env python3
import re
import socket
from threading import Thread
import json
import struct
import time
import base64

import blockchain
import signature
import kasumi
import tools
from blockchain import Transaction

"""
    alice/bob <-----> Server

    > Client script wich connects to the server via socket.
    The client sends json messages to the server, then the server
        resends the message to the right client receiever

    > The first for bytes of each message store the size of the incomming message

    > when the first message is entered the script

        1) checks if there is a secret key
            : if not  : secret key exchange with the receiever
                using Diffie Hellman key exchange protocol

        2) checks if the client public key for (RSA or El Gamal signature)
            is Initialazed
            : if not : generate and send the public to the receiver
                then receieve the receiever's public key

        3) send the kasumi ciphered signed message

"""


class ClientThread(Thread):

    def __init__(self, client_socket, signature_type="El_gamal"):
        Thread.__init__(self, daemon=True)

        self.client_name = input("Input your name : ")
        self.receiver_name = input("Input the receiver_name : ")

        self.client_socket = client_socket
        self.client_socket.send(self.client_name.encode())
        # diffie hellman dictionnary
        self.DH_dict = {}
        self.kasumi_dict = {}
        self.secret_key_initialized = False

        self.signature_type = signature_type
        self.signature_dict = {}
        self.receiver_signature_dict = {}

        self.kasumi = kasumi.Kasumi(block_cipher_type="PCBC")

    """
        Thread that listens to the socket (wich is connected to the server)
        when a message is received, it is sent to the message parser
    """

    def run(self):
        while True:
            message_length = self.client_socket.recv(4)
            if message_length != b"":
                message_length = struct.unpack(">L", message_length)[0]

                received_bytes = 0
                received_message = b""

                while received_bytes < message_length:
                    received_chunk = self.client_socket.recv(1024)
                    received_bytes = received_bytes + len(received_chunk)
                    received_message = received_message + received_chunk

                message = json.loads(received_message.decode())
                self.parse_message(message)

    """
        Message parser depending on the message type :
            : diffie_hellman
                : step 1, step 2

            : signature_init
                : RSA or El gamal

            : data
                : a classical message when all Initialization is done
    """

    def check_prime_number_files(self):
        for i in range(1, 3):
            try:
                # if there is a file OK
                with open(f"{self.client_name}_safe_512_prime_{i}", "r") as file:
                    pass
            # if not : find a prime number
            except FileNotFoundError:
                print("*** generating a safe prime number, may takes time ***")
                p = tools.find_safe_512_bits_prime()
                # save it to a file
                with open(f"{self.client_name}_safe_512_prime_{i}", "w") as file:
                    file.write(str(p))

    def load_private_key_file(self):
        try:
            # if there is a file load signature
            with open(f"{self.client_name}_private_key", "r") as file:
                self.signature_dict = json.load(file)
                pass
        # if not : generates the key
        except FileNotFoundError:
            # save it to a file
            with open(f"{self.client_name}_private_key", "w") as file:
                self.init_signature()
                json.dump(self.signature_dict, file)
        finally:
            self.send_signature_init_message()

    def send_signature_init_message(self):
        if (self.signature_type == 'RSA'):
            message = {"sender": self.client_name,
                       "receiver": self.receiver_name,
                       "message_type": "signature_init",
                       "signature_type": "RSA",
                       "n": self.signature_dict['n'], "e": self.signature_dict['e']}

        elif (self.signature_type == 'El_gamal'):
            message = {"sender": self.client_name,
                       "receiver": self.receiver_name,
                       "message_type": "signature_init",
                       "signature_type": "El_gamal",
                       "p": self.signature_dict["p"], "alpha": self.signature_dict["alpha"],
                       "h": self.signature_dict["h"]}

        self.send_json_message(json.dumps(message))

    def parse_message(self, message):
        if message["message_type"] == "diffie_hellman":
            # if step 1 is received, compute the secret and send step 2 message
            if message["diffie_hellman_step"] == 1:
                self.DH_dict["p"] = message["p"]
                self.DH_dict["A"] = message["A"]
                self.DH_dict["alpha"] = message["alpha"]

                self.DH_dict["secret_key"], self.DH_dict["B"] = signature.diffie_hellman_step_2(
                    self.DH_dict["p"],
                    self.DH_dict["alpha"],
                    self.DH_dict["A"])

                key, modified_key = self.kasumi.generate_keys(input_key=self.DH_dict["secret_key"])
                self.kasumi_dict["secret_key"] = key
                self.kasumi_dict["modified_key"] = modified_key

                message_to_send = {"sender": self.client_name,
                                   "receiver": self.receiver_name,
                                   "message_type": "diffie_hellman",
                                   "diffie_hellman_step": 2,
                                   "B": self.DH_dict["B"]}

                self.send_json_message(json.dumps(message_to_send))
                self.secret_key_initialized = True

            # if step 2 is received, comute the secret
            if message["diffie_hellman_step"] == 2:
                self.DH_dict["secret_key"] = signature.diffie_hellman_step_3(
                    message["B"], self.DH_dict["r"], self.DH_dict["p"])

                key, modified_key = self.kasumi.generate_keys(input_key=self.DH_dict["secret_key"])
                self.kasumi_dict["secret_key"] = key
                self.kasumi_dict["modified_key"] = modified_key
                self.secret_key_initialized = True

        # signature Initialization : respond to the message with the
        # same signature type
        if message["message_type"] == "signature_init":
            if message["signature_type"] == "RSA":
                self.receiver_signature_dict["n"] = message["n"]
                self.receiver_signature_dict["e"] = message["e"]
                # reçoit signature du receiver, mais générere la sienne
                # que si on en a pas encore
                if self.signature_dict == {}:
                    self.load_private_key_file()

            if message["signature_type"] == "El_gamal":
                self.receiver_signature_dict["p"] = message["p"]
                self.receiver_signature_dict["alpha"] = message["alpha"]
                self.receiver_signature_dict["h"] = message["h"]
                # reçoit signature du receiver, mais générere la sienne
                # qui si on en a pas encore*
                if self.signature_dict == {}:
                    self.load_private_key_file()

        # standad message : check signature, decipher and print the message
        if message["message_type"] == "data":
            # the cipher text is base64 encoded
            cipher_data = base64.b64decode(message["data"].encode())
            # decipher message
            clear_message = self.decipher_message(cipher_data, message["data_size"])
            # check signature
            if self.signature_type == "RSA":
                result = signature.check_RSA_signature(
                    self.receiver_signature_dict["e"],
                    self.receiver_signature_dict["n"],
                    message["signature"],
                    message=clear_message)

            if self.signature_type == "El_gamal":
                result = signature.check_El_Gamal_Signature(
                    self.receiver_signature_dict["p"],
                    self.receiver_signature_dict["alpha"],
                    self.receiver_signature_dict["h"],
                    message["signature"],
                    message=clear_message)

            print(f"\n{time.asctime()[11:-5]} " +
                  f"[ {message['sender']} ] : {clear_message}\n" +
                  f"\t\t\t\t\t\t\t\t(message verfied : {result})\n" +
                  f"\t [ {self.client_name} ] >> ", end='')

    """
        Diffie Hellman Step 1
    """

    def init_secret_key(self):
        print("*** generating secret key with diffie Hellman ***")

        with open(self.client_name + "_safe_512_prime_1", "r") as file:
            p = int(file.read())

        p, alpha, A, r = signature.diffie_hellman_step_1(p)

        self.DH_dict["p"] = p
        self.DH_dict["alpha"] = alpha
        self.DH_dict["A"] = A
        self.DH_dict["r"] = r

        message = {"sender": self.client_name,
                   "receiver": self.receiver_name,
                   "message_type": "diffie_hellman",
                   "diffie_hellman_step": 1,
                   "p": p, "alpha": self.DH_dict["alpha"],
                   "A": self.DH_dict["A"]}

        self.send_json_message(json.dumps(message))

    """
        RSA and El Gamal signature initialization
            : generate public and private key,
                and send the public key to the receiver
    """

    def init_signature(self):
        if self.signature_type == "RSA":
            print("*** Initialazing RSA signature ***")

            with open(f"{self.client_name}_safe_512_prime_1", "r") as file:
                p = int(file.read())

            with open(f"{self.client_name}_safe_512_prime_2", "r") as file:
                q = int(file.read())

            n, e, d = signature.init_RSA_Signature(p, q)

            self.signature_dict["n"] = n
            self.signature_dict["e"] = e
            self.signature_dict["d"] = d

        if self.signature_type == "El_gamal":
            print("*** Initialazing El Gamal signature ***")

            with open(f"{self.client_name}_safe_512_prime_1", "r") as file:
                p = int(file.read())

            p, alpha, h, x = signature.init_El_Gamal_Signature(p)

            self.signature_dict["p"] = p
            self.signature_dict["alpha"] = alpha
            self.signature_dict["h"] = h
            self.signature_dict["x"] = x

    # Kasumi cipher of a whole message
    def cipher_message(self, message):
        cipher = self.kasumi.cipher_message(
            message,
            self.kasumi_dict["secret_key"],
            self.kasumi_dict["modified_key"])
        return cipher

    # Kasumi decipher of a whole message
    def decipher_message(self, message, message_size):
        clear_message = self.kasumi.decipher_message(
            message,
            self.kasumi_dict["secret_key"],
            self.kasumi_dict["modified_key"])
        # Delete the kasimi padding (necessary to fill the block when needed)
        clear_message = clear_message[: message_size]
        return clear_message.decode()

    def sign_message(self, message):
        if self.signature_type == "El_gamal":
            signature_message = signature.El_Gamal_Signature(
                self.signature_dict["p"],
                self.signature_dict["alpha"],
                self.signature_dict["h"],
                self.signature_dict["x"],
                message=message
            )
        if self.signature_type == "RSA":
            signature_message = signature.RSA_Signature(
                self.signature_dict["n"],
                self.signature_dict["d"],
                message=message
            )
        return signature_message

    def generate_transaction(self, amount):
        self.signature_dict['signature_type'] = self.signature_type
        self.receiver_signature_dict['signature_type'] = self.signature_type
        new_transaction = Transaction(debit_user_public_key=blockchain.get_user_public_key(self.signature_dict),
                                      credit_user_public_key=blockchain.get_user_public_key(
                                          self.receiver_signature_dict),
                                      transaction_value=amount)
        new_transaction.sign(self.signature_dict, self.signature_type)
        return new_transaction.serialize()

    """
        Send a whole message as an encoded json serialized
        dictionnary.

        Message architecture :

            "First 32 bits : size of message" | JSON serialized dictionnary
    """

    def send_json_message(self, message):
        message = message.encode()
        message_length = struct.pack(">L", len(message))
        full_message = message_length + message
        self.client_socket.sendall(full_message)


if __name__ == '__main__':
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 8880))

    # signature : "RSA" or "El_gamal"
    client = ClientThread(client_socket, signature_type="RSA")
    client.check_prime_number_files()

    client.start()

    while True:
        print(f"\t [ {client.client_name} ] >> ", end='')
        data_input = input()

        message = {"sender": client.client_name}

        if data_input == "exit":
            message["message_type"] = "exit_message"
            message["receiver"] = "server"

            json_message = json.dumps(message)
            client.send_json_message(json_message)
            client.client_socket.close()
            break

        if re.match("^send [0-9]+(\.[0-9]+)?$", data_input):
            if client.signature_dict == {}:
                print("Please text your interlocutor before reaching the blockchain, make sure sure he or she is connected !")
                continue
            transaction_value = float(data_input[5:])
            message["message_type"] = "transaction_message"
            message["receiver"] = "server"
            message["transaction"] = client.generate_transaction(transaction_value)
            json_message = json.dumps(message)
            client.send_json_message(json_message)
            continue

        if data_input == "verify":
            message["message_type"] = "verification_message"
            message["receiver"] = "server"
            json_message = json.dumps(message)
            client.send_json_message(json_message)
            continue

        if data_input == "balance":
            if client.signature_dict == {}:
                print("Please text your interlocutor before reaching the blockchain, make sure sure he or she is connected !")
                continue
            client.signature_dict['signature_type'] = client.signature_type
            client.receiver_signature_dict['signature_type'] = client.signature_type
            message["message_type"] = "balance_message"
            message["receiver"] = "server"
            message["public_key_to_check"] = blockchain.get_user_public_key(client.signature_dict)
            json_message = json.dumps(message)
            client.send_json_message(json_message)
            continue

        if data_input != "":
            message["receiver"] = client.receiver_name
            message["data"] = data_input
            message["data_size"] = len(data_input.encode())
            message["message_type"] = "data"

            if client.DH_dict == {}:
                client.init_secret_key()
                # synchronisation, waiting for receiver Diffie hellman response
                while client.secret_key_initialized == False:
                    time.sleep(0.05)

            if client.signature_dict == {}:
                client.load_private_key_file()
                # synchronisation, waiting for receiver signature response
                while client.receiver_signature_dict == {}:
                    time.sleep(0.05)

            # sign the message
            message["signature"] = client.sign_message(message["data"])
            # cipher the message
            cipher_data = client.cipher_message(message["data"])
            # base64 encoding of the ciphertext
            message["data"] = base64.b64encode(cipher_data).decode()
            # json serialization of the dictionnary
            json_message = json.dumps(message)
            # send the whole message
            client.send_json_message(json_message)
