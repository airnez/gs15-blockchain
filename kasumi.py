#!/usr/bin/env python3

import rc4
import pyfinite.ffield

"""
    This module provides the implementation
    of the Kasumi symetric cypher.

    Includes:
        : Galois Field (GF_16) inversion
        : RC4 PRNG generating S_Boxes, and the secret
        : iterated block cipher :
            : ECB, CBC, PCBC, CTR
"""


BLOC_SIZE_BYTES = 8
KEY_BIT_SIZE = 128
NOTHING_UP_NUMBER = 0x123456789ABCDEFFEDCBA9876543210

GALOIS_FIELD_SIZE = 16

RC4_INPUT_KEY = 'LucienD&IreneeD'
INITIALIZATION_NUMBER = int.from_bytes(b"ABCDEFGH", "little")


class Kasumi():
    def __init__(self, block_cipher_type="PCBC",
                 rc4_input_key='LucienD&IreneeD)',
                 initialization_numbe_bytes=b"ABCDEFGH"):

        self.block_cipher_type = block_cipher_type
        self.rc4_prng = rc4.rc4(rc4_input_key.encode())
        self.initialization_number = int.from_bytes(initialization_numbe_bytes, "little")
        self.s_box_1 = self.rc4_prng.get_bytes(256)
        self.s_box_2 = self.rc4_prng.get_bytes(256)
        self.galois_field = pyfinite.ffield.FField(GALOIS_FIELD_SIZE)

    """
        génère clé avec RC4 ou prend une sous clé de la input_key
        (input_key vient de diffie_hellman 512 bits)

        > The "input_key" is provided by Diffie Hellman secret key exchange
    """

    def generate_keys(self, input_key=None):
        if input_key != None:
            key_bin = input_key.to_bytes(64, "little")[:16]
            key = int.from_bytes(key_bin, "little")

        key = int.from_bytes(bytearray(self.rc4_prng.get_bytes(int(KEY_BIT_SIZE/8))), 'little')
        modified_key = key ^ NOTHING_UP_NUMBER

        return key, modified_key

    """
        Take subsample of the key to generate the subkeys
    """

    def take_sub_key(self, key, sub_key_index):
        key = key.to_bytes(KEY_BIT_SIZE//8, "little")
        key = key[(sub_key_index)*2: (sub_key_index+1)*2]
        key = int.from_bytes(key, "little")

        return key

    """
        Generate the 8 sub keys
    """

    def generate_sub_key(self, key, modified_key, iteration):
        keys_dict = {}

        keys_dict["KL_i_1"] = self.left_shift(self.take_sub_key(key, iteration), 1, 16)
        keys_dict["KL_i_2"] = self.take_sub_key(modified_key, (iteration+2) % 8)

        keys_dict["KO_i_1"] = self.left_shift(self.take_sub_key(key, (iteration+1) % 8), 5)
        keys_dict["KO_i_2"] = self.left_shift(self.take_sub_key(key, (iteration+5) % 8), 8)
        keys_dict["KO_i_3"] = self.left_shift(self.take_sub_key(key, (iteration+6) % 8), 13)

        keys_dict["KI_i_1"] = self.take_sub_key(modified_key, (iteration+4) % 8)
        keys_dict["KI_i_2"] = self.take_sub_key(modified_key, (iteration+3) % 8)
        keys_dict["KI_i_3"] = self.take_sub_key(modified_key, (iteration+7) % 8)

        return keys_dict

    """
        circual bitwise right shift
            : int : integer to manipulate
            : i : size of the sift
            : nb_bits : size of the integer
    """

    def right_shift(self, int, i, nb_bits=16):
        result = (int >> i) | ((int & (2 ** i - 1)) << (nb_bits - i))
        return result

    """
        circual bitwise left shift
            : int : integer to manipulate
            : i : size of the sift
            : nb_bits : size of the integer
    """

    def left_shift(self, int, i, nb_bits=16):
        result = (int & (2**(nb_bits - i) - 1)) << i | (int >> (nb_bits - i))
        return result

    """
        Python generator that yields blocks of data from a file
    """

    def lecture_bloc(self, file, byte_bloc_size):
        last_iteration = False
        while not last_iteration:
            data = file.read(byte_bloc_size)
            if data == b"":
                break
            yield data

    """
        kasumi FI function, with S_box modification
    """

    def FI(self, y, z):
        z_bytes = z.to_bytes(2, "little")
        z_1 = z_bytes[0]  # LSB
        z_2 = z_bytes[1]  # MSB

        z_1 = self.s_box_1[z_1]
        z_2 = self.s_box_2[z_2]

        z = z_1.to_bytes(1, "little") + z_2.to_bytes(1, "little")
        z = int.from_bytes(z, "little")

        x = self.right_shift(y, 2, nb_bits=8) ^ (z)
        return x

    """
        kasumi FL function with Galois inversion modification
    """

    def FL(self, x, keys_dict):
        x_bytes = x.to_bytes(4, "little")

        l = x_bytes[:2]  # LSB
        r = x_bytes[2:]  # MSB

        l = int.from_bytes(l, "little")
        r = int.from_bytes(r, "little")

        r_dash = self.left_shift(l & keys_dict["KL_i_1"], 1) ^ r
        l_dash = self.left_shift(r_dash | keys_dict["KL_i_2"], 1) ^ l

        r_dash_inv = self.galois_field.Inverse(r_dash)
        l_dash_inv = self.galois_field.Inverse(l_dash)

        r_dash_inv = r_dash_inv.to_bytes(2, "little")
        l_dash_inv = l_dash_inv.to_bytes(2, "little")

        x_dash = int.from_bytes(r_dash_inv + l_dash_inv, "little")

        return x_dash

    def FO(self, x, keys_dict):
        x_bytes = x.to_bytes(4, "little")

        l = x_bytes[:2]  # LSB
        r = x_bytes[2:]  # MSB

        l = int.from_bytes(l, "little")
        r = int.from_bytes(r, "little")

        for j in range(1, 4):
            new_r = self.FI(keys_dict["KI_i_"+str(j)], l ^ keys_dict["KO_i_"+str(j)]) ^ r
            l = r
            r = new_r

        l = l.to_bytes(2, "little")
        r = r.to_bytes(2, "little")

        x_dash = int.from_bytes(l+r, "little")

        return x_dash

    """
        Kasumi feistel cipher of one block
    """

    def kasumi_feistel_encryption(self, clear_block, key, modified_key):
        L = clear_block[:4]  # LSB
        R = clear_block[4:]  # MSB

        L = int.from_bytes(L, "little")
        R = int.from_bytes(R, "little")

        for iteration in range(0, 8):

            keys_dict = self.generate_sub_key(key, modified_key, iteration)
            # even
            if iteration % 2 == 0:
                new_L = self.FO(self.FL(L, keys_dict), keys_dict) ^ R
                R = L
                L = new_L
            # odd
            if iteration % 2 == 1:
                new_L = self.FL(self.FO(L, keys_dict), keys_dict) ^ R
                R = L
                L = new_L

        L = L.to_bytes(4, "little")
        R = R.to_bytes(4, "little")

        cipher_block = int.from_bytes(L+R, "little")

        return cipher_block

    """
        Kasumi feistel decipher of one block
    """

    def kasumi_feistel_decryption(self, cipher_block, key, modified_key):
        L = cipher_block[:4]  # LSB
        R = cipher_block[4:]  # MSB

        L = int.from_bytes(L, "little")
        R = int.from_bytes(R, "little")

        for iteration in reversed(range(0, 8)):
            keys_dict = self.generate_sub_key(key, modified_key, iteration)
            # even
            if iteration % 2 == 0:
                new_L = R
                R = self.FO(self.FL(R, keys_dict), keys_dict) ^ L
                L = new_L
            # odd
            if iteration % 2 == 1:
                new_L = R
                R = self.FL(self.FO(R, keys_dict), keys_dict) ^ L
                L = new_L

        L = L.to_bytes(4, "little")
        R = R.to_bytes(4, "little")

        clear_block = int.from_bytes(L+R, "little")

        return clear_block

    """
        Kasumi feistel cipher of a whole message
            : key provided by diffie hellman key exchange protocol
            : iterated block cipher
    """

    def cipher_message(self, message, key, modified_key):
        cipher_message = b""
        bin_message = message.encode()
        num_blocks = len(bin_message) // 8

        if num_blocks > 0:
            if self.block_cipher_type == "ECB":
                for i in range(0, num_blocks+1):
                    clear_block = bin_message[(i)*BLOC_SIZE_BYTES: (i+1)*BLOC_SIZE_BYTES]
                    cipher_block = self.kasumi_feistel_encryption(clear_block, key, modified_key)
                    cipher_block = cipher_block.to_bytes(8, "little")
                    cipher_message = cipher_message + cipher_block

            if self.block_cipher_type == "CBC":
                vect = INITIALIZATION_NUMBER
                for i in range(0, num_blocks+1):
                    clear_block = bin_message[(i)*BLOC_SIZE_BYTES: (i+1)*BLOC_SIZE_BYTES]
                    clear_block = vect ^ int.from_bytes(clear_block, "little")
                    clear_block = clear_block.to_bytes(8, "little")
                    cipher_block = self.kasumi_feistel_encryption(clear_block, key, modified_key)
                    vect = cipher_block

                    cipher_block = cipher_block.to_bytes(8, "little")
                    cipher_message = cipher_message + cipher_block

            if self.block_cipher_type == "PCBC":
                vect = INITIALIZATION_NUMBER
                for i in range(0, num_blocks+1):
                    clear_block = bin_message[(i)*BLOC_SIZE_BYTES: (i+1)*BLOC_SIZE_BYTES]

                    xored_clear_block = vect ^ int.from_bytes(clear_block, "little")
                    xored_clear_block = xored_clear_block.to_bytes(8, "little")
                    cipher_block = self.kasumi_feistel_encryption(
                        xored_clear_block, key, modified_key)
                    vect = int.from_bytes(clear_block, "little") ^ cipher_block

                    cipher_block = cipher_block.to_bytes(8, "little")
                    cipher_message = cipher_message + cipher_block

            if self.block_cipher_type == "CTR":
                vect = 0
                for i in range(0, num_blocks+1):
                    clear_block = bin_message[(i)*BLOC_SIZE_BYTES: (i+1)*BLOC_SIZE_BYTES]

                    cipher_vect = self.kasumi_feistel_encryption(
                        vect.to_bytes(8, "little"), key, modified_key)

                    cipher_block = int.from_bytes(clear_block, "little") ^ cipher_vect
                    vect = vect + 1

                    cipher_block = cipher_block.to_bytes(8, "little")
                    cipher_message = cipher_message + cipher_block
        else:
            cipher_message = self.kasumi_feistel_encryption(bin_message, key, modified_key)
            cipher_message = cipher_message.to_bytes(8, "little")

        return cipher_message

    """
        Kasumi feistel decipher of a whole message
            : key provided by diffie hellman key exchange protocol
            : iterated block cipher
    """

    def decipher_message(self, cipher_message_bin, key, modified_key):
        clear_message = b""
        num_blocks = len(cipher_message_bin) // 8

        if num_blocks > 1:
            if self.block_cipher_type == "ECB":
                for i in range(0, num_blocks):
                    cipher_block = cipher_message_bin[i*BLOC_SIZE_BYTES: (i+1)*BLOC_SIZE_BYTES]
                    clear_block = self.kasumi_feistel_decryption(cipher_block, key, modified_key)
                    clear_block = clear_block.to_bytes(8, "little")

                    clear_message = clear_message + clear_block

            if self.block_cipher_type == "CBC":
                vect = INITIALIZATION_NUMBER
                for i in range(0, num_blocks):
                    cipher_block = cipher_message_bin[i*BLOC_SIZE_BYTES: (i+1)*BLOC_SIZE_BYTES]
                    clear_block = self.kasumi_feistel_decryption(cipher_block, key, modified_key)
                    clear_block = clear_block ^ vect

                    vect = int.from_bytes(cipher_block, "little")
                    clear_block = clear_block.to_bytes(8, "little")

                    clear_message = clear_message + clear_block

            if self.block_cipher_type == "PCBC":
                vect = INITIALIZATION_NUMBER
                for i in range(0, num_blocks):
                    cipher_block = cipher_message_bin[i*BLOC_SIZE_BYTES: (i+1)*BLOC_SIZE_BYTES]
                    clear_block = self.kasumi_feistel_decryption(cipher_block, key, modified_key)
                    clear_block = clear_block ^ vect

                    vect = clear_block ^ int.from_bytes(cipher_block, "little")
                    clear_block = clear_block.to_bytes(8, "little")

                    clear_message = clear_message + clear_block

            if self.block_cipher_type == "CTR":
                vect = 0
                for i in range(0, num_blocks+1):
                    cipher_block = cipher_message_bin[(i)*BLOC_SIZE_BYTES: (i+1)*BLOC_SIZE_BYTES]

                    cipher_vect = self.kasumi_feistel_encryption(
                        vect.to_bytes(8, "little"), key, modified_key)

                    clear_block = int.from_bytes(cipher_block, "little") ^ cipher_vect
                    vect = vect + 1

                    clear_block = clear_block.to_bytes(8, "little")
                    clear_message = clear_message + clear_block
        else:
            clear_message = self.kasumi_feistel_decryption(cipher_message_bin, key, modified_key)
            clear_message = clear_message.to_bytes(8, "little")

        return clear_message

    """
        kasumi cipher and decipher a file
    """

    def kasumi_demo(self):
        with open("fichier_clair", "rb") as clear_file:
            with open("fichier_chiffre", "wb") as crypted_file:
                for clear_block in lecture_bloc(clear_file, BLOC_SIZE_BYTES):
                    crypted_block = self.kasumi_feistel_encryption(clear_block, key, modified_key)
                    crypted_file.write(crypted_block.to_bytes(8, "little"))

        with open("fichier_chiffre", "rb") as crypted_file:
            with open("new_clear_file", "wb") as new_file:
                for crypted_block in lecture_bloc(crypted_file, BLOC_SIZE_BYTES):
                    clear_block = self.kasumi_feistel_decryption(crypted_block, key, modified_key)
                    new_file.write(clear_block.to_bytes(8, "little"))
