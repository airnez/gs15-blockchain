#!/usr/bin/env python3

import random
from rc4 import rc4

BLOC_SIZE_BYTES = 8

KEY_BIT_SIZE = 128

NOTHING_UP_NUMBER = 0x123456789ABCDEFFEDCBA9876543210

RC4_INPUT_KEY = 'LucienD&IreneeD'
rc4_prng = rc4(RC4_INPUT_KEY.encode())

S_BOX_1 = rc4_prng.get_bytes(256)

S_BOX_2 = rc4_prng.get_bytes(256)


"""
    : encode :
        : encode les str vers bytes, avec utf8 à défaut

    : decode :
        decode des bytes, vers utf8 à défaut


    > plus facile de travailler avec les bits sous
    forme d'entiers que de bytes (car pas d'opérations entre bytes)


    > vaux mieux bosser en little endian
        : permet d'avoir a[0] : octet LSB
            et MSB a la fin


    > iteration ; de 0 à 7,
        donc inverse fonctions Fi, entre pair et impair
"""



"""
    à générer avec RC4, clé de 128 bits

"""
def generate_keys():
    key = int.from_bytes(bytearray(rc4_prng.get_bytes(int(KEY_BIT_SIZE/8))), 'little')
    toXOR = int.from_bytes(bytearray(rc4_prng.get_bytes(int(KEY_BIT_SIZE/8))), 'little')
    modified_key = key ^ toXOR

    return key, modified_key

"""
    récup une portion de 16 bits de la clé de 128
"""
def take_sub_key(key, sub_key_index):
    key = key.to_bytes(KEY_BIT_SIZE//8, "little")
    key = key[(sub_key_index)*2 : (sub_key_index+1)*2]
    key = int.from_bytes(key, "little")

    return key

"""
    iteration : de 0 à 7
"""
def generate_sub_key(key, modified_key, iteration):

    keys_dict = {}

    keys_dict["KL_i_1"] = left_shift( take_sub_key(key, iteration), 1, 16)
    keys_dict["KL_i_2"] = take_sub_key(modified_key, (iteration+2)%8 )

    keys_dict["KO_i_1"] = left_shift( take_sub_key(key, (iteration+1)%8) , 5)
    keys_dict["KO_i_2"] = left_shift( take_sub_key(key, (iteration+5)%8), 8)
    keys_dict["KO_i_3"] = left_shift( take_sub_key(key, (iteration+6)%8), 13)

    keys_dict["KI_i_1"] = take_sub_key(modified_key, (iteration+4)%8)
    keys_dict["KI_i_2"] = take_sub_key(modified_key, (iteration+3)%8)
    keys_dict["KI_i_3"] = take_sub_key(modified_key, (iteration+7)%8)

    return keys_dict

def right_shift(int, i, nb_bits=16):

    result = ( int >> i) | (( int & (2** i - 1)) << (nb_bits - i))
    return result

def left_shift(int, i, nb_bits=16):

    result = (int & (2**(nb_bits - i) - 1) ) << i  | (int >> (nb_bits - i))
    return result

def lecture_bloc(file, byte_bloc_size):
    last_iteration = False

    while  not last_iteration:
        data = file.read(byte_bloc_size)

        if data == b"":
            break

        yield data

def FI(y, z):

    z_bytes = z.to_bytes(2, "little")
    z_1 = z_bytes[0] # LSB
    z_2 = z_bytes[1] # MSB

    z_1 = S_BOX_1[z_1]
    z_2 = S_BOX_2[z_2]


    z = z_1.to_bytes(1,"little") + z_2.to_bytes(1,"little")
    z = int.from_bytes(z, "little")

    x = right_shift(y, 2, nb_bits=8) ^ (z)

    return x

def FL(x, keys_dict):
    x_bytes = x.to_bytes(4, "little")

    l = x_bytes[:2] # LSB
    r = x_bytes[2:] # MSB

    l = int.from_bytes(l, "little")
    r = int.from_bytes(r, "little")

    r_dash = left_shift( l and keys_dict["KL_i_1"] , 1 ) ^ r
    l_dash = left_shift( r_dash or keys_dict["KL_i_2"] , 1 ) ^ l

    r_dash = r_dash.to_bytes(2, "little")
    l_dash = l_dash.to_bytes(2, "little")

    x_dash = int.from_bytes(l_dash + r_dash, "little")

    return x_dash

def FO(x, keys_dict):
    x_bytes = x.to_bytes(4, "little")

    l = x_bytes[:2] # LSB
    r = x_bytes[2:] # MSB

    l = int.from_bytes(l, "little")
    r = int.from_bytes(r, "little")

    for j in range(1,4):
        new_r = FI(keys_dict["KI_i_"+str(j)], l ^ keys_dict["KO_i_"+str(j)] ) ^ r
        l = r
        r = new_r

    l = l.to_bytes(2,"little")
    r = r.to_bytes(2,"little")

    x_dash = int.from_bytes(l+r, "little")

    return x_dash

def kasumi_feistel_encryption(clear_block, key, modified_key):

    L = clear_block[:4] # LSB
    R = clear_block[4:] # MSB

    L = int.from_bytes(L,"little")
    R = int.from_bytes(R,"little")

    for iteration in range(0, 8):

        keys_dict = generate_sub_key(key, modified_key, iteration)

        # even
        if iteration % 2 == 0:
            new_L = FO( FL(L, keys_dict), keys_dict) ^ R
            R = L
            L = new_L

        #odd
        if iteration %2 == 1:
            new_L = FL( FO(L ,keys_dict) ,keys_dict) ^ R
            R = L
            L = new_L

    L = L.to_bytes(4,"little")
    R = R.to_bytes(4,"little")

    crypted_block = int.from_bytes(L+R, "little")

    return crypted_block

def kasumi_feistel_decryption(crypted_block, key, modified_key):


        L = crypted_block[:4] # LSB
        R = crypted_block[4:] # MSB

        L = int.from_bytes(L,"little")
        R = int.from_bytes(R,"little")

        for iteration in reversed(range(0, 8)):

            keys_dict = generate_sub_key(key, modified_key, iteration)

            # even
            if iteration % 2 == 0:
                new_L = R
                R = FO( FL(R, keys_dict), keys_dict) ^ L
                L = new_L

            #odd
            if iteration %2 == 1:
                new_L = R
                R = FL( FO(R ,keys_dict) ,keys_dict) ^ L
                L = new_L

        L = L.to_bytes(4,"little")
        R = R.to_bytes(4,"little")

        clear_block = int.from_bytes(L+R, "little")

        return clear_block

def kasumi_demo():
    with open("fichier_clair", "rb") as clear_file:
        with open("fichier_chiffre", "wb") as crypted_file:
            for clear_block in lecture_bloc(clear_file, BLOC_SIZE_BYTES):
                crypted_block = kasumi_feistel_encryption(clear_block, key, modified_key)
                crypted_file.write(crypted_block.to_bytes(8,"little"))

    with open("fichier_chiffre", "rb") as crypted_file:
        with open("new_clear_file", "wb") as new_file:
            for crypted_block in lecture_bloc(crypted_file, BLOC_SIZE_BYTES):
                clear_block = kasumi_feistel_decryption(crypted_block, key, modified_key)
                new_file.write(clear_block.to_bytes(8,"little"))


if __name__ == '__main__':

    key, modified_key = generate_keys()

    with open("fichier_clair", "rb") as clear_file:
        for clear_block in lecture_bloc(clear_file, BLOC_SIZE_BYTES):
            crypted_block = kasumi_feistel_encryption(clear_block, key, modified_key)
            decrypted_block = kasumi_feistel_decryption(crypted_block.to_bytes(8,"little"), key, modified_key)

            print(f"{clear_block} => {crypted_block.to_bytes(8,'little')}"+
                f"=> {decrypted_block.to_bytes(8,'little')}")

            input()
