#!/usr/bin/env python3

import tools
import random
import time

# a retirer quand la fonction de Hash sera implémentée
import hashlib




def init_El_Gamal_Signature(p):

    alpha = tools.find_generator(p)

    x = random.randint(1, p-2)

    h = tools.fast_exponentiation(alpha, x, mod=p)

    print(f"El gamal publc key : \n\n\t\tp:{hex(p)} \n\n\t\talpha:{hex(alpha)}, \n\n\t\th:{hex(h)})")

    pub_key = {"p":p, "alpha":alpha, "h":h}

    return pub_key, x

def El_Gamal_Signature(pub_key, x, message=None, file_name=None):
    p = pub_key["p"]
    alpha = pub_key["alpha"]
    h = pub_key["h"]

    if message == None and file_name == None:
        print("error : please enter a message or a filname to sign")

    y = random.randint(1, p-2)

    while not tools.rabin_Miller_test(y):
        y = random.randint(1, p-2)

    if file_name != None:
        with open(file_name, "r") as file:
            message = file.read()

    h_M = hashlib.md5(message.encode()).digest()
    h_M = int.from_bytes(h_M, "little")

    print(f"Hash :  {hex(h_M)}")

    _, __, y_inv = tools.PGCD_bezout(y, p-1)

    s_1 = tools.fast_exponentiation(alpha, y, mod=p)
    s_2 = y_inv * (h_M - x*s_1) % (p-1)

    return [s_1, s_2]


def check_El_Gamal_Signature(pub_key, signature, message=None, file_name=None):
    if message == None and file_name == None:
        print("error : please enter a message or a filname to sign")

    p = pub_key["p"]
    alpha = pub_key["alpha"]
    h = pub_key["h"]

    s_1 = signature[0]
    s_2 = signature[1]

    if file_name != None:
        with open(file_name, "r") as file:
            message = file.read()

    h_M = hashlib.md5(message.encode()).digest()
    h_M = int.from_bytes(h_M, "little")

    test_1 = (tools.fast_exponentiation(h, s_1, mod=p) * tools.fast_exponentiation(s_1, s_2, mod=p) ) % p
    test_2 = tools.fast_exponentiation(alpha, h_M, mod=p)

    if test_1 == test_2:
        print("signature OK")
        return True
    else:
        print("signature not OK")
        return False

if __name__ == '__main__':

    #Alice

    with open("alice_safe_512_prime_1","r") as file:
        p = int(file.read())

    pub_key, x = init_El_Gamal_Signature(p)


    signature = El_Gamal_Signature(pub_key, x, message="coucou c'est moi")


    # Bon :  connait pub pub_key

    check_El_Gamal_Signature(pub_key, signature, message="coucou c'est moi")
