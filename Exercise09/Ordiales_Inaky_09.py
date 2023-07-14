#!/usr/bin/python3
# The following code assumes that PyCryptodome has been installed using
#   pip install pycryptodomex
# Documentation for PyCryptodome
#   https://pycryptodome.readthedocs.io/en/latest/

#=====================================================================
# IÑAKY ORDIALES CABALLERO --------------------------------- May 2023.
#=====================================================================


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
    #TODO: implement this function
    # Explanation: here it was really easy we just had to generate the coefficients
    #   calling our generateCoefficients function and then for all the n parties we
    #   evaluated the polinomial. We then added to the list that we will return the
    #   pair (x, y) for the polinomial.
    shares = []
    coeffs = []

    coeffs = generateCoefficients(x, f, q)

    for i in range(1, n+1):
        polVal = polynomial(i, coeffs, f, q)
        shares.append((i, polVal))

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
    #TODO: implement this function
    # Explanation: we just added the secret as the first coefficient and then we 
    #   generated the other f random coefficients for our polinomial of degree f
    #   with f+1 coeffs. 
    coeffs = []
    coeffs.append(x)
    for i in range(0,f):
        coeffs.append(random.randint(0, q))
    return coeffs


"""
Function that evaluates the polynomial.

Args:
    val: value to evaluate the polynomial
    coefficients: the list of coefficients
    f: threshold 
    q: the prime number

Returns:
    total: a polynomial value
"""
def polynomial(val, coefficients, f, q):
    #TODO: implement this function
    # Explanation: evaluating the polinomial is just a for loop that goes through the
    #   coefficients and multiplies by the value given elevated to its corresponding
    #   degree.
    polVal = 0
    for i in range(0, f+1):
        polVal += (coefficients[i]*power(val, i, q))
        polVal %= q
    return polVal



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
Function that reconstructs the secret from f + 1 shares.

Args:
    shares: list of f + 1 shares
    q: the prime number

Returns:
    result: reconstructed value
"""
def reconstruct(shares, q):
    #TODO: implement this function
    # Explanation: this was definitely the most difficult part of the exercise, and the one
    #   that made me fully understand the (f+1)-of-n secret sharing scheme. During the lecture
    #   I did not understand that for the lagrange coefficient we were using x values and not
    #   y. After looking the formula online I saw that it was with x (hence my shares are pairs(x,y)).
    #   After this I also got problems with the result because my inexact division modulo q gave me nan.
    #   Thanks to the template given where there is the operation of modInverse, I remembered that
    #   modular division of integers is not straightforward and instead is the modInverse(denom)*numerator.
    #   With that I just did a nested for loop for separately calculating all the numerators and denominators
    #   of the terms added to build up the secret. Then I added the proper term (doing the steps for integer modular division).
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


"""
Function that computes an inverse of x modulo q.

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


def main():
    q = number.getPrime(1024)
    print ('q =', q)
    n = number.getRandomRange(10, 100)
    print('n =', n)
    f = number.getRandomRange(1, n//2)
    print ('f = ', f)
    # generate a secret x
    x = number.getRandomRange(0, q)
    
    # generate shares 
    shares = share(x, f, n, q)
    
    # genereate a subset of shares
    s = random.sample(shares, f+1)
    
    # reconstruct the secret 
    reconstructed = reconstruct(s, q)

    print('\n\nshared secret = ' + str(x))
    print('\nreconstructed = ' + str(reconstructed))
    
    assert(x == reconstructed)

    print("\nSuccess in the exercise!!!\n")

main()

