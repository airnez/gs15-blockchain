#!/usr/bin/env python3

import random
import os

"""
    This module provides some useful functions
        : generate random 512 integer
        : comute the PGCD(a,b)
        : find safe prime numbers
        : fast exponentiation
        : inverse calculation in Z_p
        : find a generator in Z_p
"""


mask_512 = (1 << 512) - 1
state = random.randint(0, 2**512-1)

"""
    Implementation of 512 bits Xorshift
"""


def random_512_bits_integer():
    global state
    x = state
    x = x ^ (x << 13) & mask_512
    x = x ^ (x >> 17) & mask_512
    x = x ^ (x << 5) & mask_512
    state = x
    return x


"""
    Find a 512 safe prime number, with Rabin Miller test
"""


def find_safe_512_bits_prime():
    n = random_512_bits_integer()
    while len(bin(n)) != 514:
        n = random_512_bits_integer()

    print("n : "+str(n)+" bit : "+str(len(bin(n))))

    if n % 2 == 0:
        n = n-1

    while True:
        # skip obvious not prime numbers
        if (n % 3 != 0) or (n % 5 != 0) or (n % 7 != 0) or (n % 9 != 0) or \
            (n % 11 != 0) or (n % 13 != 0) or (n % 13 != 0) or \
            (n % 17 != 0) or (n % 19 != 0) or (n % 21 != 0) or (n % 23 != 0) or \
                (n % 25 != 0) or (n % 27 != 0) or (n % 29 != 0):

            if rabin_Miller_test(n) == True:
                q = (n-1)//2
                if rabin_Miller_test(q) == True:
                    print(f"{n} is safe prime : q : {q}")
                    return n
        n = n+2


"""
    rabin miller test on n, odd integer
"""


def rabin_Miller_test(n, iterations=5):
    n_minus_one = n - 1
    s = 0
    d = 0

    while n_minus_one % 2 == 0:
        n_minus_one = n_minus_one // 2
        s = s+1
    d = n_minus_one

    it = 0

    for i in range(iterations):
        a = random.randint(2, n-1)
        x = fast_exponentiation(a, d, mod=n)

        if (x == 1) or (x == n-1):
            continue

        for r in range(1, s):
            x = (x**2) % n
            if x == 1:
                return False
            if x == n-1:
                continue

        return False
    return True


"""
    Compute efficiently a ^ b mod n
"""


def fast_exponentiation(a, b, mod=1):
    result = 1
    i = 1
    while b != 0:
        if b % 2 == 1:
            result = (result * a) % mod
        a = (a*a) % mod

        i = i+1
        b = b//2

    return result


"""
    Find a generator in Z_p , p is a safe prime number
"""


def find_generator(safe_prime):
    q = (safe_prime-1)//2
    i = 0

    for alpha in range(2, safe_prime-1):
        i = i+1
        if (alpha ** 2 % safe_prime) == 1:
            continue
        if fast_exponentiation(alpha, q, mod=safe_prime) == 1:
            continue
        return alpha


"""
    Extended Euclide algorithm, y_n is the inverse of a mod b
"""


def PGCD_bezout(a, b):
    if a < b:
        a, b = b, a
    r = [a, b]
    q = []
    x = [1, 0]
    y = [0, 1]
    i = 2

    while r[len(r)-1] != 0:

        q_i = r[i-2]//r[i-1]
        r_i = r[i-2] % r[i-1]

        q.append(q_i)
        r.append(r_i)

        x.append(q_i*x[i-1] + x[i-2])
        y.append(q_i*y[i-1] + y[i-2])

        i = i+1

    x_n = (-1)**(len(x)) * x[len(x)-2]
    y_n = (-1)**(len(y) + 1) * y[len(y)-2]

    return r[len(r)-2], x_n, y_n


if __name__ == '__main__':

    with open("alice_safe_512_prime_1", "r") as file:
        safe_prime = int(file.read())
        alpha = find_generator(safe_prime)
        print(alpha)

    with open("alice_safe_512_prime_2", "r") as file:
        safe_prime = int(file.read())
        alpha = find_generator(safe_prime)
        print(alpha)

    with open("bob_safe_512_prime_1", "r") as file:
        safe_prime = int(file.read())
        alpha = find_generator(safe_prime)
        print(alpha)

    with open("bob_safe_512_prime_2", "r") as file:
        safe_prime = int(file.read())
        alpha = find_generator(safe_prime)
        print(alpha)
