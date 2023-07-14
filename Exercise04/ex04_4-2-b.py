#!/usr/bin/python3

# Parameter generation and implementation of ElGamal cryptosystem
# based on the Diffie-Hellman key exchange
# The following code assumes that PyCryptodome has been installed using
#   pip install pycryptodomex
# Documentation for PyCryptodome
#   https://pycryptodome.readthedocs.io/en/latest/

from Cryptodome.Random import random
from Cryptodome.Util import number
import matplotlib.pyplot as plt
import time

# Modular exponentiation using square-and-multiply method
#
# a: base
# x: exponent
# p: modulus
# returns (a^x) mod p computed using O(log p) steps
#
def power(a, x, p):
    res = 1
    a = a % p
    if a == 0:
        return 0
    while x > 0:
        # Square if exponent is even
        if (x & 1) == 0:
            a = (a * a) % p
            x = x >> 1
        # Multiply if exponent is odd
        else:
            res = (res * a) % p
            x = x - 1
    return res


# Generation of a random element in the subgroup
#
# q: prime
# p: prime such that q divides p - 1
# returns a random element in the subgroup of order q modulo p
#
def randomsubgroup(q, p):
    while True:
        h = random.randint(2, p-1)
        g = power(h, (p-1)// q, p)
        if g != 1:
            break
    return g


# Generation of system parameters
#
# qbits: bit length of q, the subgroup of prime order q
# pbits: bit length of p, the modulus
# returns (g, q, p), where g is a generator of the subgroup of order q mod p
#
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


# Key generation for a user given the established g, p and q
#
# g: fixed generator of cyclic group subset of Zp
# p: modulus parameter
# q: order of cyclic group Zp
# returns a pair of keys (public key, secret key)
#
# for secret key uses a random subgroup generator and elevates it to
# a random int less than q and takes its modulo p.
#
def keyGen(g, q, p):
    x = power(randomsubgroup(q,p), random.randint(2,q-1), p)
    y = power(g,x,p)
    return (y, x) 






# MAXIMUM VALUE FOR NUMBER
maxV = pow(2,20)

# Encryption of number
#
# y: public key of user
# m: message
# g, q, p: established parameters for cyclic group and subset generator
# returns (R,C) a pair of the cyphertext
#
# for r it generates a random element of cyclic group Zp, then for each
# element of the plain text it changes it to ascii and operates it.
#
def enc(y, m, g, q, p):
    r = power(randomsubgroup(q,p), random.randint(2,q-1), p)
    R = power(g,r,p)
    C = []

    for e in m:
        C.append( power(g,e,p)*power(y,r,p) )

    m_enc = (R,C)
    return m_enc


# Decryption of cyphertext into plain text
#
# x: secret key of user
# m_enc: pair (R,C) of cyphertext to decrypt
# p: established modulus operator
#
# if decrypts each element using private key and generates
# a number 
#
def dec(x, m_enc, p, maxvalue):
    R = m_enc[0]
    C = m_enc[1]

    m_dec = []

    for e in C:
        h = e//power(R,x,p)
        for i in range(0,maxvalue):
            if (power(g,i,p) - h == 0.0):
                m_dec.append(i)
                continue
    return m_dec



# ELGAMAL ADDITIVE HOMOMORPHIC ENCRYPTION

# COULD NOT DO IT THIS WAY, TAKES TOO LONG


# # Generating parameters
# (g, q, p) = Parameters(160, 1024) # For testing only! INSECURE!
# #(g, q, p) = Parameters(256, 2024) # For use in practice

# # Bob generates its public key and private key
# pk_B, sk_B = keyGen(g, q, p)


# # Trying the times

# maxV = 260

# res = []
# for i in range(256, maxV):
#     m = list(range(1,i))
#     start = time.time()
#     m_enc = enc(pk_B, m, g, q, p)
#     m_dec = dec(sk_B, m_enc, p, i)
#     end = time.time()
#     res.append(end-start)

# # Generating parameters
# #(g, q, p) = Parameters(160, 1024) # For testing only! INSECURE!
# (g, q, p) = Parameters(256, 2024) # For use in practice

# # Bob generates its public key and private key
# pk_B, sk_B = keyGen(g, q, p)

# res2 = []
# for i in range(256, maxV):
#     m = list(range(1,i))
#     start = time.time()
#     m_enc = enc(pk_B, m, g, q, p)
#     m_dec = dec(sk_B, m_enc, p, i)
#     end = time.time()
#     res2.append(end-start)



maxV = 4096


# Generating parameters
(g, q, p) = Parameters(160, 1024) # For testing only! INSECURE!
#(g, q, p) = Parameters(256, 2024) # For use in practice

# Bob generates its public key and private key
pk_B, sk_B = keyGen(g, q, p)

res = []
for i in range (256, maxV):
    m = [i]
    start = time.time()
    m_enc = enc(pk_B, m, g, q, p)
    m_dec = dec(sk_B, m_enc, p, i)
    end = time.time()
    res.append(end-start)

# Generating parameters
#(g, q, p) = Parameters(160, 1024) # For testing only! INSECURE!
(g, q, p) = Parameters(256, 2024) # For use in practice

# Bob generates its public key and private key
pk_B, sk_B = keyGen(g, q, p)

res2 = []
for i in range (256, maxV):
    m = [i]
    start = time.time()
    m_enc = enc(pk_B, m, g, q, p)
    m_dec = dec(sk_B, m_enc, p, i)
    end = time.time()
    res2.append(end-start)



plt.plot(list(range(256, maxV)), res, 'b-', list(range(256,maxV)), res2, 'r-')
plt.ylabel("time in s")
plt.xlabel("max value")
plt.title("max number increase vs time increase")
plt.show()
