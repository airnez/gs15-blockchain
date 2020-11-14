#!/usr/bin/env python3

import binascii
import random

BLOC_SIZE_BYTES = 8

KEY_BIT_SIZE = 128
"""
    : encode :
        : encode les str vers bytes, avec utf8 à défaut

    : decode :
        decode des bytes, vers utf8 à défaut



"""



"""
    générer avec RC4, clé de 128 bits

"""
def generate_key():
    key = random.randint(2**(KEY_BIT_SIZE-1), 2**KEY_BIT_SIZE-1)

    return key

"""
    version de base, mais peut améliorer sub key type DES

    : iteration : 1 à 8
"""
def generate_sub_keys(key, iteration):
    key = bin(key)[2:]

    return key[(iteration-1)*16 : iteration*16]

def right_shift(int, i):
    length = int.bit_length()
    print(length)

    result = ( int >> i) | (( int & (2** i - 1)) << (length - i))
    return result

def left_shift(int, i):
    length = int.bit_length()

    result = (int & (2**(length - i) - 1) ) << i  | (int >> (length - i))
    return result



def lecture_bloc(file, byte_bloc_size):
    last_iteration = False

    while  not last_iteration:
        data = file.read(byte_bloc_size)

        if data == b"":
            break

        yield data

if __name__ == '__main__':
    """
    with open("fichier_clair", "rb") as file:
        for i in lecture_bloc(file, BLOC_SIZE_BYTES):
            print(i)
            input()"""
