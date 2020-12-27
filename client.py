#!/usr/bin/env python3

import socket
from threading import Thread
import json
import struct
import time
import base64

import signature
import kasumi


"""
    utilise struct :
        : écrit la taille sur 4 octets, envoie avec sendall(data)
        taille + message encodé en b""

        : autre coté : lit 4 octets, puis attend de receptionner toutes les
            données

    > si clé  DH None  :
      envoie step 1, (si reçoit step 1 : action puis envoi step2)

     > si dict signature None : envoi clé pub et attend une clé pub

     > enfin : envoi message chiffré / signé

     ===========> Le cipher text n'est pas JSON serialisable :
        donc on le passe d'abord en base64 :

         m = input_clair

         signe m
         chiffre m
         c64  base64(chiffré)

         envoie taille m  et le chiffré

         ==========

         chiffré = b64decode (c64)
         m = decihper(chiffré)
         m = m[: taille_m]
         sign = sign(m)

    >>> message["data_size"] : contient taille du message avant chiffrement,
        car Kasumi fait un paddind pour arroundir a la taille du bloc.
        Une fois déchiffré on retir le padding, puis check signature

"""

class ClientThread(Thread):

    def __init__(self, client_socket, signature_type="El_gamal"):

        Thread.__init__(self, daemon=True)

        self.client_name = input("Input your name : ")
        self.reciever_name = input("Input the reciever_name : ")

        self.client_socket = client_socket
        self.client_socket.send(self.client_name.encode())

        self.DH_dict = {}

        self.kasumi_dict = {}

        self.signature_type = signature_type
        self.signature_dict = {}
        self.reciever_signature_dict = {}

    """
        Thread qui écoute le socket du client, reçoit un message et
        appelle le parser de message
    """
    def run(self):

        while  True:

            message_length = self.client_socket.recv(4)

            if message_length != b"":

                message_length = struct.unpack(">L", message_length)[0]

                recieved_bytes = 0
                recieved_message = b""

                while  recieved_bytes < message_length:

                    recieved_chunk = self.client_socket.recv(1024)
                    recieved_bytes = recieved_bytes + len(recieved_chunk)

                    recieved_message = recieved_message + recieved_chunk

                message = json.loads(recieved_message.decode())

                self.parse_message(message)

    """
        Parse un message Json, peut etre de type diffie_hellman (init),
        signature(RSA / El_gamal) (init signature)
            ou "data" si c'est un message classique
    """
    def parse_message(self, message):

        if message["message_type"] == "diffie_hellman":
            # si reçoit step 1 : calcule le scret et envoie la step 2
            if message["diffie_hellman_step"] == 1:

                self.DH_dict["p"] =  message["p"]
                self.DH_dict["A"] = message["A"]
                self.DH_dict["alpha"] = message["alpha"]

                self.DH_dict["secret_key"], self.DH_dict["B"] = signature.diffie_hellman_step_2(
                    self.DH_dict["p"],
                    self.DH_dict["alpha"],
                    self.DH_dict["A"])

                key, modified_key = kasumi.generate_keys(input_key=self.DH_dict["secret_key"])
                self.kasumi_dict["secret_key"] = key
                self.kasumi_dict["modified_key"] = modified_key

                message_to_send =  {"sender":self.client_name,
                    "receiver":self.reciever_name,
                    "message_type":"diffie_hellman",
                    "diffie_hellman_step":2,
                    "B":self.DH_dict["B"]}

                self.send_json_message(json.dumps(message_to_send))

            # si reçoit step 2 calcule le secret
            if message["diffie_hellman_step"] == 2:

                self.DH_dict["secret_key"] = signature.diffie_hellman_step_3(
                    message["B"], self.DH_dict["r"], self.DH_dict["p"])

                key, modified_key = kasumi.generate_keys(input_key=self.DH_dict["secret_key"])
                self.kasumi_dict["secret_key"] = key
                self.kasumi_dict["modified_key"] = modified_key

        # init de la signature : Alice envoie la sienne et bob générer et envoie
        # la sienne
        if message["message_type"] == "signature_init":

            if message["signature_type"] == "RSA":

                self.reciever_signature_dict["n"] = message["n"]
                self.reciever_signature_dict["e"] = message["e"]

                # reçoit signature du receiver, mais générere la sienne
                # que si on en a pas encore
                if self.signature_dict == {}:
                    self.init_signature()

            if message["signature_type"] == "El_gamal":

                self.reciever_signature_dict["p"] = message["p"]
                self.reciever_signature_dict["alpha"] = message["alpha"]
                self.reciever_signature_dict["h"] = message["h"]

                # reçoit signature du receiver, mais générere la sienne
                # qui si on en a pas encore*
                if self.signature_dict == {}:
                    self.init_signature()

        # parse un message classique: : data chiffré et signé
        if message["message_type"] == "data":
            # cipher text en base 64
            cipher_data = base64.b64decode(message["data"].encode())
            # decipher message
            clear_message = self.decipher_message(cipher_data, message["data_size"])
            # checl signature
            if self.signature_type == "RSA":

                result = signature.check_RSA_signature(
                    self.reciever_signature_dict["e"],
                    self.reciever_signature_dict["n"],
                    message["signature"],
                    message=clear_message)

            if self.signature_type == "El_gamal":

                result = signature.check_El_Gamal_Signature(
                    self.reciever_signature_dict["p"],
                    self.reciever_signature_dict["alpha"],
                    self.reciever_signature_dict["h"],
                    message["signature"],
                    message=clear_message)

            print(f"\n[ {message['sender']} ] : {clear_message}\n"+\
                f"\t\t\t\t\t\t\t\t(message verfied : {result})\n"+\
                f"[ {self.client_name} ] >> ",end='')

    """
        Step 1 de Diffie Hellman
    """
    def init_secret_key(self):

        print("*** generating secret key with diffie Hellman ***")

        with open(self.client_name+"_safe_512_prime_1", "r") as file:
            p = int(file.read())

        p, alpha, A, r = signature.diffie_hellman_step_1(p)

        self.DH_dict["p"] = p
        self.DH_dict["alpha"] = alpha
        self.DH_dict["A"] = A
        self.DH_dict["r"] = r

        message = {"sender":self.client_name,
            "receiver":self.reciever_name,
            "message_type":"diffie_hellman",
            "diffie_hellman_step":1,
            "p":p, "alpha":self.DH_dict["alpha"],
            "A":self.DH_dict["A"]}

        self.send_json_message(json.dumps(message))

    def init_signature(self):

        if self.signature_type == "RSA":

            print("*** Initialazing RSA signature ***")

            with open(self.client_name+"_safe_512_prime_1", "r") as file:
                p = int(file.read())

            with open(self.client_name+"_safe_512_prime_2", "r") as file:
                q = int(file.read())

            n, e, d = signature.init_RSA_Signature(p, q)

            self.signature_dict["n"] = n
            self.signature_dict["e"] = e
            self.signature_dict["d"] = d

            message = {"sender":self.client_name,
                "receiver":self.reciever_name,
                "message_type":"signature_init",
                "signature_type":"RSA",
                "n":n, "e":e}

            self.send_json_message(json.dumps(message))

        if self.signature_type == "El_gamal":

            print("*** Initialazing El Gamal signature ***")

            with open(self.client_name+"_safe_512_prime_1","r") as file:
                p = int(file.read())

            p, alpha, h, x = signature.init_El_Gamal_Signature(p)

            self.signature_dict["p"] = p
            self.signature_dict["alpha"] = alpha
            self.signature_dict["h"] = h
            self.signature_dict["x"] = x

            message = {"sender":self.client_name,
                "receiver":self.reciever_name,
                "message_type":"signature_init",
                "signature_type":"El_gamal",
                "p":p, "alpha":alpha, "h":h}

            self.send_json_message(json.dumps(message))

    # chiffre un message avec kasumi, rnvoi un bin
    def cipher_message(self, message):

        cipher = kasumi.kasumi_cipher_message(
            message,
            self.kasumi_dict["secret_key"],
            self.kasumi_dict["modified_key"])

        return cipher

    # cipher message : bin, renvoie str
    def decipher_message(self, message, message_size):

        clear_message = kasumi.kasumi_decipher_message(
            message,
            self.kasumi_dict["secret_key"],
            self.kasumi_dict["modified_key"])

        # supprime le padding de kasumi (arroundi taille bloc)
        clear_message = clear_message[: message_size]

        return clear_message.decode()

    # signature du message
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

    """
        envoie le message complet au destinataire

        Arch message :

        'taille en 32 bits | contenu en JSON serialisé'

    """
    def send_json_message(self, json_message):

        message = json_message.encode()
        message_length = struct.pack(">L", len(message))

        full_message = message_length + message

        self.client_socket.sendall(full_message)


if __name__ == '__main__':

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 8880))

    client = ClientThread(client_socket, signature_type="RSA")
    client.start()

    while  True:

        print(f"[ {client.client_name} ] >> ",end='')
        data_input = input()

        if data_input == "exit":
            client.client_socket.close()
            break

        if data_input != "":

            message =  {}
            message["sender"] = client.client_name
            message["receiver"] = client.reciever_name
            message["data"] = data_input
            message["data_size"] = len(data_input.encode())
            message["message_type"] = "data"

            if client.DH_dict == {}:
                client.init_secret_key()

                # synchronisation 1 sec: pour attendre la réponse de bob
                try:
                    client.DH_dict["secret_key"]
                except KeyError:
                    time.sleep(1)

            if client.signature_dict == {}:
                client.init_signature()

                # synchronisation 1 sec: pour attendre la réponse de bob
                if client.reciever_signature_dict == {}:
                    time.sleep(1)

            message["signature"] = client.sign_message(message["data"])

            cipher_data = client.cipher_message(message["data"])
            message["data"] = base64.b64encode(cipher_data).decode()

            json_message = json.dumps(message)
            client.send_json_message(json_message)
