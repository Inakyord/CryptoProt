#!/usr/bin/python3
# The following code assumes that PyCryptodome has been installed using
#   pip3 install pycryptodomex
# Documentation for PyCryptodome
#   https://pycryptodome.readthedocs.io/en/latest/
# This code works with pyhton version 3.7.4 

from Cryptodome.Random import random
from Cryptodome.Util import number

"""
Function that shares a secret x.

Args:
    x: the secret
    f: threshold
    n: number of shares
    q: the prime number

Returns:
    list: a list of n shares
"""
def share(x, f, n, q):
    coefficients = generateCoefficients(x,f,q)
    shares = []
    for i in range(n):
        val = random.randint(0, q-1)
        share = polynomial(val, coefficients, f, q)
        shares.append((val,share))
    return shares

"""
Function that generates a list of coefficients.

Args:
    x: the secret
    f: threshold 
    q: the prime number

Returns:
    coefficients: a list of coefficients
"""
def generateCoefficients(x, f, q):
    coefficients = []
    for i in range(1, f + 1):
        coefficients.append(random.randint(0, q-1))
    coefficients.append(x)
    return coefficients


"""
Function that compute polynomial value.

Args:
    val: some random value
    coefficients: the list of coefficients
    f: threshold 
    q: the prime number

Returns:
    total: a polynomial value
"""
def polynomial(val, coefficients, f, q):
    total = 0;
    for i, coeff in enumerate(coefficients):
        total =  (total + coeff * power(val, (f - i), q)) % q 
    return total

"""
Utility function for modular exponentiation.

Args:
    x: base 
    e: exponent
    p: modulus 

Returns:
    result: (a^x) mod p 

"""
def power(x, e, p):
    result = 1
    x = x % p
    if (x == 0):
        return 0
    while (e > 0):
        if ((e & 1) == 0):
            x = (x * x) % p
            e = e >> 1
        else:
            result = (result * x) % p
            e = e - 1
    return result

"""
Computes inverted value such that x * inverted mod q = 1

Args:
    x: the GF(q) element that is to be inverted
    q: the prime number

Returns:
    inverted: inverted value

"""
def modInverse(x, q):
    if x < 0 :
        x = q + x
    inverted = power(x, q-2, q)
    return inverted

"""
Generation of a random element in the subgroup.

Args:
    q: prime
    p: prime such that q divides p - 1

Returns:
    g: a random element in the subgroup of order q modulo p

"""
def randomsubgroup(q, p):
    while True:
        h = random.randint(2, p-1)
        g = power(h, (p-1)//q, p)
        if (g != 1):
            break
    return g

"""
Generation of system parameters.

Args:
    qbits: bit length of q, the subgroup of prime order q
    pbits: bit length of p, the modulus

Returns:
    (g, q, p): g is a generator of the subgroup of order q mod p

"""
def Parameters(qbits, pbits):
    while True:
        while True:
            q = random.getrandbits(qbits)
            if (number.isPrime(q)):
                break
        m = random.getrandbits(pbits - qbits - 1)
        p = m * q + 1
        if (number.isPrime(p)):
            break
    g = randomsubgroup(q, p)
    return (g, q, p)

"""
Function that implements key generation.

Args:
    p, q, g: g is a generator of the subgroup of order q mod p
    n: number of shares
    f: treshold

Returns:
    (pk, shares): a global public key and a share sk_i for each party x_i
"""
def KeyGen(p,q,g,n,f):
    s = random.randint(2, q-1)
    shares = share(s, f, n, q)
    pk = power(g,s,p)
    return (pk, shares)

"""
Function that implements textbook ElGamal encryption.

Args:
    p, q, g: g is a generator of the subgroup of order q mod p
    pk: public key
    m: a message we want to encrypt

Returns:
    (R, C): encrypted message
"""
def encrypt(p,q,g,pk,m):
    r = random.randint(2, q-1)
    R = power(g, r, p)
    C = (power(pk, r, p) * m) % p 
    return (R,C)


"""
Function that implements textbook ElGamal decryption.

Args:
    p, q, g: g is a generator of the subgroup of order q mod p
    pk: public key
    sk: a share
    c: a ciphertext

Returns:
    (x_i,d_i): a decryption share d_i for party x_i 
"""
def decrypt(p,q,g,pk,sk,c):
    (x_i,sk_i) = sk
    (R,C) = c
    d_i = power(R,sk_i,p)
    return (x_i,d_i)

"""
Function that decrypts ciphertext c to a message m.

Args:
    p, q, g: g is a generator of the subgroup of order q mod p
    D: a list of t + 1 decryption shares
    c: a ciphertext

Returns:
    val: reconstructed message m
"""
def recover(p,q,g,D,c):
    (R,C) = c
    prod = 1
    for i,share_i in enumerate(D):
        x_i,d_i = share_i
        exp = 1
        for j,share_j in enumerate(D):
            x_j, d_j = share_j
            if i != j :
                exp = (exp * (x_j%q) * modInverse(x_j - x_i,q)) % q
        prod = (prod * power(d_i,exp,p)) % p
    val = (C * modInverse(prod,p)) % p
    return val

def main():
    (g, q, p) = Parameters(160, 1024)     # For testing only! INSECURE!
    # (g, q, p) = Parameters(256, 2024)     # For use in practice

    n = number.getRandomRange(10, 100)
    print ('n =', n)
    f = number.getRandomRange(1, int(n/2))
    print ('f = ', f)

    # generate a message m
    m = number.getRandomRange(2, p-1)

    pk, shares = KeyGen(p,q,g,n,f)
    
    c = encrypt(p,q,g,pk,m)

    # genereate a subset of shares
    s = random.sample(shares, f+1)
    
    D = []
    for s_i in s:
        D.append(decrypt(p,g,q,pk,s_i,c))

    reconstructed = recover(p,q,g,D,c)

    print ('message = ' + str(m))
    print ('reconstructed = ' + str(reconstructed))
    
    assert(m == reconstructed)

main()