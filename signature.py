#!/usr/bin/env python3

import tools
import random
from spongeHash import sponge_hash

#================ EL Gamal Signature =================

"""
    pub key : p , alpha, h
"""
def init_El_Gamal_Signature(p):

    alpha = tools.find_generator(p)

    x = random.randint(1, p-2)

    h = tools.fast_exponentiation(alpha, x, mod=p)

    #²(f"El gamal publc key : \n\n\t\tp:{hex(p)} \n\n\t\talpha:{hex(alpha)}, \n\n\t\th:{hex(h)})")

    return p, alpha, h , x

"""
    pub key : p , alpha, h
"""
def El_Gamal_Signature(p, alpha, h, x, message=None, file_name=None):

    if message == None and file_name == None:
        print("error : please enter a message or a filname to sign")

    y = random.randint(1, p-2)

    while not tools.rabin_Miller_test(y):
        y = random.randint(1, p-2)

    if file_name != None:
        with open(file_name, "r") as file:
            message = file.read()

    h_M = sponge_hash(message.encode(), hash_length_bytes=32)
    h_M = int.from_bytes(h_M, "little")

    _, __, y_inv = tools.PGCD_bezout(y, p-1)

    s_1 = tools.fast_exponentiation(alpha, y, mod=p)
    s_2 = y_inv * (h_M - x*s_1) % (p-1)

    return [s_1, s_2]

"""
    pub key : p , alpha, h
"""
def check_El_Gamal_Signature(p, alpha, h, signature, message=None, file_name=None):

    if message == None and file_name == None:
        print("error : please enter a message or a filname to sign")

    s_1 = signature[0]
    s_2 = signature[1]

    if file_name != None:
        with open(file_name, "r") as file:
            message = file.read()

    h_M = sponge_hash(message.encode(), hash_length_bytes=32)
    h_M = int.from_bytes(h_M, "little")

    test_1 = (tools.fast_exponentiation(h, s_1, mod=p) * tools.fast_exponentiation(s_1, s_2, mod=p) ) % p
    test_2 = tools.fast_exponentiation(alpha, h_M, mod=p)

    if test_1 == test_2:
        return True
    else:
        return False

#=====================  RSA Signature   ==================================

"""
    pub key  : n and e
"""
def init_RSA_Signature(p, q):

    phi = (p-1)*(q-1)
    n = p * q

    e = tools.random_512_bits_integer()
    if e%2 == 0: e = e+1


    while True:
        if (n % 3 != 0) or (n % 5 != 0) or (n % 7 != 0) or (n % 9 != 0) or \
            (n % 11 != 0)  or (n % 13 != 0)  or (n % 13 != 0)  or \
            (n % 17 != 0)  or (n % 19 != 0):
            if tools.rabin_Miller_test(e):
                break

        e = e+2

    _, __, d = tools.PGCD_bezout(e, phi)
    if d < 0 : d = d%phi

    pub_key = {"n":n, "e":e}

    return n, e, d

"""
    pub key  : n and e
"""
def RSA_Signature(n, d, message=None, file_name=None):

    if message == None and file_name == None:
        print("error : please enter a message or a filname to sign")
        return 0

    if file_name != None:
        with open(file_name, "r") as file:
            message = file.read()

    h_M = sponge_hash(message.encode(), hash_length_bytes=32)
    h_M = int.from_bytes(h_M, "little")

    #print(f"hash : {hex(h_M)}")

    signature = tools.fast_exponentiation(h_M, d, mod=n)

    return signature

"""
    pub key  : n and e
"""
def check_RSA_signature(e, n, signature, message=None, file_name=None):

    if message == None and file_name == None:
        print("error : please enter a message or a filname to check")
        return 0

    if file_name != None:
        with open(file_name, "r") as file:
            message = file.read()

    h_M = sponge_hash(message.encode(), hash_length_bytes=32)
    h_M = int.from_bytes(h_M, "little")

    test = tools.fast_exponentiation(signature, e, mod=n)

    if test == h_M:
        return True
    else:
        return False

# ======================  Diffie Hellman   =================================


#Alice
"""
    pub_key : alpha, p, alpha**r
"""
def diffie_hellman_step_1(p):

    alpha = tools.find_generator(p)
    r = random.randint(1, p-1)
    A = tools.fast_exponentiation(alpha, r, mod=p)

    return p, alpha, A, r

#Bob
def diffie_hellman_step_2(p, alpha, A):

    s = random.randint(1, p-1)

    B = tools.fast_exponentiation(alpha, s, mod=p)

    secret = tools.fast_exponentiation(A, s, mod=p)

    return secret, B

#Alice
def diffie_hellman_step_3(B, r, p):

    secret = tools.fast_exponentiation(B, r, mod=p)

    return secret


if __name__ == '__main__':

    def test_el_gamal():
        #Alice
        with open("alice_safe_512_prime_1","r") as file:
            p = int(file.read())

        pub_key, x = init_El_Gamal_Signature(p)

        signature = El_Gamal_Signature(pub_key, x, message="coucou c'est moi")

        # Bob :  connait pub pub_key

        check_El_Gamal_Signature(pub_key, signature, message="coucou c'est moi")

    def test_rsa():
        # alice
        with open("alice_safe_512_prime_1","r") as file:
            p = int(file.read())

        with open("alice_safe_512_prime_2","r") as file:
            q = int(file.read())

        pub_key, d = init_RSA_Signature(p,q)

        signature = RSA_Signature(pub_key, d, "coucou c'est moi")

        #bob :
        check_RSA_signature(pub_key, signature, message="coucou c'est moi")

    def test_diffie_hellamn():

        #Alice
        with open("alice_safe_512_prime_1","r") as file:
            p = int(file.read())

        data, r = diffie_hellman_step_1(p)

        #Bob
        secret_bob, data2 = diffie_hellman_step_2(data)

        #Alice
        secret_alice = diffie_hellman_step_3(data2, r, data["p"])

        if secret_alice == secret_bob:
            print("oui")
