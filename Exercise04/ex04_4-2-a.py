#!/usr/bin/python3

# Parameter generation and implementation of ElGamal additive homomorphic cryptosystem
# based on the Diffie-Hellman key exchange
# The following code assumes that PyCryptodome has been installed using
#   pip install pycryptodomex
# Documentation for PyCryptodome
#   https://pycryptodome.readthedocs.io/en/latest/

from Cryptodome.Random import random
from Cryptodome.Util import number

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
maxV = pow(2,10)

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
    C = power(g,m,p)*power(y,r,p)
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
def dec(x, m_enc, p):
    R = m_enc[0]
    C = m_enc[1]
    h = C/power(R,x,p)
    for i in range(0,maxV):
        if (power(g,i,p) - h == 0.0):
            return i
    return -1



# ELGAMAL ADDITIVE HOMOMORPHIC ENCRYPTION


# Generating parameters
(g, q, p) = Parameters(160, 1024) # For testing only! INSECURE!
#(g, q, p) = Parameters(256, 2024) # For use in practice


# Alice generates its public key and private key
pk_A, sk_A = keyGen(g, q, p)


# Bob generates its public key and private key
pk_B, sk_B = keyGen(g, q, p)




# Alice generates 2 random numbers and its sum
m_original_A1 = random.randint(0, maxV)
m_original_A2 = random.randint(0, maxV)
m_sum = (m_original_A1 + m_original_A2)

print("\nFirst number:\n "+str(m_original_A1))
print("\nSecond number:\n "+str(m_original_A2))
print("\nSum of both:\n "+str(m_sum))


# Alice encrypts both numbers separately and its sum
m_enc1 = enc(pk_B, m_original_A1, g, q, p)
m_enc2 = enc(pk_B, m_original_A2, g, q, p)

m_encs = ((m_enc1[0]*m_enc2[0])%p, (m_enc1[1]*m_enc2[1])%p)


# Bob then proceeds to decrypt both numbers and its sum.
m_dec1 = dec(sk_B, m_enc1, p, m_original_A1, m_original_A2)
m_dec2 = dec(sk_B, m_enc2, p, m_original_A1, m_original_A2)
m_decs = dec(sk_B, m_encs, p, m_original_A1, m_original_A2)

print("\nDecrypted first:\n "+str(m_dec1))
print("\nDecrypted second:\n "+str(m_dec2))
print("\nDecrypted enc(first)+enc(second):\n "+str(m_decs))

