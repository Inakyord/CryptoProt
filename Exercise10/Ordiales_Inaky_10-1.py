#!/usr/bin/python3

# The following code assumes that PyCryptodome has been installed using
#   pip install pycryptodomex
# Documentation for PyCryptodome
#   https://pycryptodome.readthedocs.io/en/latest/

#=====================================================================
# IÑAKY ORDIALES CABALLERO --------------------------------- May 2023.
#=====================================================================


######################################
##                                  ##
## Threshold ElGamal cryptosystem   ##
##                                  ##
######################################

from Cryptodome.Random import random
from Cryptodome.Util import number
from Cryptodome.Hash import SHA256



#************************************#
#   Functions of threshold ElGamal   #
#____________________________________#


"""
Key generation function:
  Generates a public key and n shares of the secret key

  Args:
    g: field generator
    q: field size
    p: prime number
    f: faulty parties
    n: total parties
  
  Returns:
    list: (pk, (skeys))
"""
def KeyGen(g, q, p, f, n):
    
    x = random.randint(2, q-1)
    y = power(g, x, p)

    keys = []
    keys.append(x)
    keys.append(y)
    xi = share(x, f, n, p)
    keys.append(xi)

    return keys


"""
Encryption function:
  Encrypts a message m into cyphertex (R,C)

  Args:
    g, q, p: global parameters
    pk:      public key
    m:       message to encrypt

  Returns:
    cyphertext pair (R, C)
"""
def Enc(g, q, p, pk, m):
    r = random.randint(2, q-1)
    R = power(g, r, p)
    value = power(pk, r, p)
    value = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    hash_value = SHA256.new(value).digest()
    hash_value = int.from_bytes(hash_value, 'big')
    C = m ^ (hash_value)
    return (R, C)


"""
Decryption function:
  Computes a decryption share di.

  Args:
    ski: secret key share
    R: cyphertext
    p: prime number

  Returns:
    decrypted share and party's number

"""
def Dec(ski, R, p):
    di = power(R, ski[1], p)
    return (ski[0], di)


"""
Recover function:
  Recovers the message encrypted using f+1 shares.

  Args:
    D: list of decrypted shares
    C: cyphertext
    p: prime number

  Returns:
    decrypted recovered message
"""
def Recover(S, C, p, q):

    n = len(S)
    value = 1

    for i in range(0, n):
        numerator   = 1
        denominator = 1
        for j in range(0, n):
            if i!=j:
                numerator   *= S[j][0]
                numerator   %= p
                denominator *= (S[j][0] - S[i][0])
                denominator %= p
        lamb   = modInverse(denominator, p) * numerator
        lamb  %= p
        value *= power(S[i][1], lamb, p)
        value %= p

    value = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    hash_value = SHA256.new(value).digest()
    hash_value = int.from_bytes(hash_value, 'big')

    m = hash_value ^ C

    return m



#************************************#
#   Auxiliary functions for KeyGen   #
#____________________________________#


# Generation of system parameters
#   qbits: bit length of q, the subgroup of prime order q
#   pbits: bit length of p, the modulus
#
#   returns (g, q, p), where g is a generator of the subgroup of order q mod p
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


# Generation of a random element in the subgroup
#   q: prime
#   p: prime such that q divides p - 1
#
#   returns a random element in the subgroup of order q modulo p
#
def randomsubgroup(q, p):
    while True:
        h = random.randint(2, p-1)
        g = power(h, (p-1)//q, p)
        if g != 1:
            break
    return g


"""
Function that shares a secret x.
  x: the secret
  f: threshold 
  n: number of shares
  p: the prime number
  
  returns a list of n shares.
"""
def share(x, f, n, p):
    shares = []
    coeffs = []

    coeffs = generateCoefficients(x, f, p)

    for i in range(1, n+1):
        polVal = polynomial(i, coeffs, f, p)
        shares.append((i, polVal))

    return shares


"""
Function that generates a list of coefficients.
  x: the secret
  f: threshold 
  p: the prime number

  returns a list of coefficients
"""
def generateCoefficients(x, f, p):
    coeffs = []
    coeffs.append(x)
    for i in range(0,f):
        coeffs.append(random.randint(0, p-1))
    return coeffs


"""
Function that evaluates the polynomial.
  val: value to evaluate the polynomial
  coefficients: the list of coefficients
  f: threshold 
  p: the prime number

  returns a polynomial value
"""
def polynomial(val, coefficients, f, p):
    polVal = 0
    for i in range(0, f+1):
        polVal += (coefficients[i]*power(val, i, p))
        polVal %= p
    return polVal




#************************************#
#          Utility functions         #
#____________________________________#


"""
Utility function for modular exponentiation.
  x: base 
  e: exponent
  p: modulus 

  returns (a^x) mod p 
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
Utility function that computes an inverse of x modulo p.
  x: the GF(q) element that is to be inverted
  q: the prime number

  returns inverted value
"""
def modInverse(x, p):
    if x < 0 :
        x = p + x
    inverted = power(x, p-2, p)
    return inverted


"""
Function that reconstructs the secret from f + 1 shares.
  shares: list of f + 1 shares
  q: the prime number

  returns reconstructed value
"""
def reconstruct(shares, q):
    numerator   = 1
    denominator = 1
    secret      = 0
    l = len(shares)

    for i in range(0, l):
        numerator   = 1
        denominator = 1
        for j in range (0, l):
            if i != j:
                numerator   *= shares[j][0]
                numerator   %= q
                denominator *= (shares[j][0]-shares[i][0])
                denominator %= q

        numerator *= shares[i][1]

        # numerator / denominator
        secret += modInverse(denominator, q) * numerator
        secret %= q

    return secret





#----------------------------------------------------------#
#                                                          #
#       Main body of the programm, case of use.            #
#                                                          #
#----------------------------------------------------------#


def main():

    # Parameters: 
    #   g - generator
    #   q - size of group generated
    #   p - prime number (mod)
    #(g, q, p) = Parameters(160, 1024)     # For testing only! INSECURE!
    (g, q, p) = Parameters(256, 2048)

    # Parties:
    #   n = total parties
    #   f = faulty parties
    n = number.getRandomRange(10, 100)
    print('n =', n)
    f = number.getRandomRange(1, n//2)
    print('f =', f)

    
    # Key generation
    # Using sk for decryption tests.
    # skeys are the shares
    (sk, pk, skeys) = KeyGen(g, q, p, f, n)

    # Encryption
    m = random.getrandbits(256)
    #m = 10
    print('\nMessage: ', m)

    (R, C) = Enc(g, q, p, pk, m)
    print('\nMessage Encrypted.')
    print('R = ', R)
    print('C = ', C)

#-------------- Checking for partial points in the process, not part of solution -----------

    # Checking for decryption with secret key:
    val = power(R, sk, p)
    val = val.to_bytes((val.bit_length() + 7) // 8, 'big')
    hash_val = SHA256.new(val).digest()
    hash_val = int.from_bytes(hash_val, 'big')
    res = hash_val ^ C
    print('\n\nDecryption with secret key.')
    print('Message: ', res)


    # generate a subset of shares
    s = random.sample(skeys, f+1)

    # Checking for secret key reconstruction with shares.
    skrec = reconstruct(s, p)
    print('\n\nReconstruction of secret key.')
    print('Sk = ', sk)
    print('Skr= ', skrec)

    assert (sk == skrec)


# ----------------- Starting solution decryption -------------------
    

    # getting decrypted shares for everyone
    D = []
    for ski in skeys:
        (pos, di) = Dec(ski, R, p)
        D.append((pos, di))

    # Choosing random f+1 samples to use on reconstruction.
    S = random.sample(D, f+1)

    reconstructed = Recover(S, C, p, q)

    print('\n\nDecryption with shares.')
    print("\n\nEncrypted message = " + str(m))
    print("Decrypted message = "+ str(reconstructed))
    
    print("\n\nChecking exercise...\n\n")

    assert (m == reconstructed)

    print("\nSuccess in the exercise!!!\n")



# Main body execution
main()

# JM: Your solution is not working correctly. I suspect that the problem is in the key generation function.
# Also recovery function does not work correctly.
# Please read our solution carefully and try correcting your code.
# Total: 5/10 points for the effort.