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

#======================================================================

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
    print(f"d : {bin(d).count('1')}")

    pub_key = {"n":n, "e":e}


    print(f"public key :\nn : {hex(n)}\ne : {hex(e)} et {len(bin(e))}")

    return pub_key, d

def RSA_Signature(pub_key, d, message=None, file_name=None):

    n = pub_key["n"]

    if message == None and file_name == None:
        print("error : please enter a message or a filname to sign")
        return 0

    if file_name != None:
        with open(file_name, "r") as file:
            message = file.read()

    h_M = hashlib.md5(message.encode()).digest()
    h_M = int.from_bytes(h_M, "little")

    print(f"hash : {hex(h_M)}")

    signature = tools.fast_exponentiation(h_M, d, mod=n)

    print(f"signature : {hex(signature)}")

    return signature

def check_RSA_signature(pub_key, signature, message=None, file_name=None):

    if message == None and file_name == None:
        print("error : please enter a message or a filname to check")
        return 0

    if file_name != None:
        with open(file_name, "r") as file:
            message = file.read()

    e = pub_key["e"]
    n = pub_key["n"]

    h_M = hashlib.md5(message.encode()).digest()
    h_M = int.from_bytes(h_M, "little")

    test = tools.fast_exponentiation(signature, e, mod=n)

    if test == h_M:
        print("signature OK")
        return True
    else:
        print("signature not OK")
        return False

# =======================================================

#Alice
def diffie_hellman_step_1(p):

    alpha = tools.find_generator(p)
    r = random.randint(1, p-1)
    A = tools.fast_exponentiation(alpha, r, mod=p)

    data_to_send = {"p":p, "alpha":alpha, "A":A}

    return data_to_send, r

#Bob
def diffie_hellman_step_2(data_recieved):

    p = data_recieved["p"]
    alpha = data_recieved["alpha"]
    A = data_recieved["A"]

    s = random.randint(1, p-1)

    B = tools.fast_exponentiation(alpha, s, mod=p)

    data_to_send = {"B":B}

    secret = tools.fast_exponentiation(A, s, mod=p)
    print(f"BOB secret : {hex(secret)}")

    return secret, data_to_send

#Alice
def diffie_hellman_step_3(data_recieved, r, p):
    B = data_recieved["B"]

    secret = tools.fast_exponentiation(B, r, mod=p)

    print(f"Alice secret : {hex(secret)}")


    return secret


if __name__ == '__main__':

    def check_el_gamal():
        #Alice
        with open("alice_safe_512_prime_1","r") as file:
            p = int(file.read())

        pub_key, x = init_El_Gamal_Signature(p)

        signature = El_Gamal_Signature(pub_key, x, message="coucou c'est moi")

        # Bob :  connait pub pub_key

        check_El_Gamal_Signature(pub_key, signature, message="coucou c'est moi")

    def check_rsa():
        # alice
        with open("alice_safe_512_prime_1","r") as file:
            p = int(file.read())

        with open("alice_safe_512_prime_2","r") as file:
            q = int(file.read())

        pub_key, d = init_RSA_Signature(p,q)

        signature = RSA_Signature(pub_key, d, "coucou c'est moi")

        #bob :
        check_RSA_signature(pub_key, signature, message="coucou c'est moi")

    def check_diffie_hellamn():

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
