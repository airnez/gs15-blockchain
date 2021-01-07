#!/usr/bin/env python3

import tools
import random
from spongeHash import sponge_hash

"""
    This module provides the implementation of
        : El Gamal signature
        : RSA Signature
        : Diffie Hellman key exchange protocol
"""

# ================ EL Gamal Signature =================

"""
    Initialization of El Gamal Signature,
    Public Key : p, alpha, h
    Private key : x
"""


def init_El_Gamal_Signature(p):
    alpha = tools.find_generator(p)
    x = random.randint(1, p-2)
    h = tools.fast_exponentiation(alpha, x, mod=p)
    return p, alpha, h, x


"""
    Signe a message or a file with El Gamal signature,
    using spongeHash function
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
    Verify an El Gamal signature of a message (string) or a file
    using the public key
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

    test_1 = (tools.fast_exponentiation(h, s_1, mod=p) *
              tools.fast_exponentiation(s_1, s_2, mod=p)) % p

    test_2 = tools.fast_exponentiation(alpha, h_M, mod=p)

    if test_1 == test_2:
        return True
    else:
        return False

# =====================  RSA Signature   ==================================


"""
    Initialization of RSA signature
    Public Key : n , e
    Private Key : d
"""


def init_RSA_Signature(p, q):
    phi = (p-1)*(q-1)
    n = p * q

    e = tools.random_512_bits_integer()
    if e % 2 == 0:
        e = e+1
    # find e, as PGCD( e, phi(n)) = 1
    while True:
        if (n % 3 != 0) or (n % 5 != 0) or (n % 7 != 0) or (n % 9 != 0) or \
            (n % 11 != 0) or (n % 13 != 0) or (n % 13 != 0) or \
                (n % 17 != 0) or (n % 19 != 0):
            if tools.rabin_Miller_test(e):
                break

        e = e+2

    _, __, d = tools.PGCD_bezout(e, phi)
    if d < 0:
        d = d % phi

    pub_key = {"n": n, "e": e}

    return n, e, d


"""
    RSA Signature of a file or a message (string)
    using spongeHash function
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

    signature = tools.fast_exponentiation(h_M, d, mod=n)
    return signature


"""
    Check RSA Signature of a file or mesage using the public key
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


"""
    First step of Diffie Hellman protocol :
    : p : big prime number of 512 bits
"""


def diffie_hellman_step_1(p):
    alpha = tools.find_generator(p)
    r = random.randint(1, p-1)
    A = tools.fast_exponentiation(alpha, r, mod=p)
    return p, alpha, A, r


"""
    Second step of Diffie Hellman protocol :
        : compute alpha ^ s mod p (the secret)
"""


def diffie_hellman_step_2(p, alpha, A):
    s = random.randint(1, p-1)
    B = tools.fast_exponentiation(alpha, s, mod=p)
    secret = tools.fast_exponentiation(A, s, mod=p)
    return secret, B


"""
    Last step of Diffie Hellman protocol
    Compute the secret
"""


def diffie_hellman_step_3(B, r, p):
    secret = tools.fast_exponentiation(B, r, mod=p)
    return secret
