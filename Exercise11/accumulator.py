import time
import secrets
import hashlib
import random


def miller_rabin(n: int, k=5) -> bool:

    s = n - 1
    d = 0
    while s % 2 == 0:
        s = s // 2
        d += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x != 1:
            i = 0
            while x != (n-1):
                if i == d-1:
                    return False
                else:
                    i += 1
                    x = (x**2) % n

    return True


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    return miller_rabin(n)


def hash_to_prime(input: str, seed: int) -> int:
    random.seed(seed)
    hash = hashlib.sha256(str(input).encode())
    p = int(hash.hexdigest(), 16) * 2**(64)+1

    while not is_prime(p):
        p += 2

    return p


class Accumulator:
    def __init__(self,  p: int, q: int, n=1000, seed=None, security=2048):
        self.p = p
        self.q = q
        self.N = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)

        if seed is None:
            seed = time.time_ns()
        self.seed = seed

        self.n = n
        self.x = ["" for _ in range(self.n)]
        self.w = [0] * self.n
        self.security = security
        self.r = secrets.randbelow(self.N)
        self.H = lambda i, x: hash_to_prime(str(i)+x, self.seed)

        prod = 1
        for i in range(self.n):
            px = self.H(i, self.x[i])
            prod *= pow(px, -1, self.phi) % self.N
        self.alpha = pow(self.r, prod, self.N)

        for i in range(self.n):
            p = self.H(i, self.x[i])
            self.w[i] = pow(self.alpha, pow(p, -1, self.phi), self.N)

    def update(self, i: int, v: str) -> bool:
        if self.x[i] == v:
            return False

        pv = self.H(i, v)
        px = self.H(i, self.x[i])
        hi = pow(px, -1, self.phi)
        self.alpha = pow(self.alpha, hi*pv, self.N)
        for j in range(self.n):
            if j != i:
                self.w[j] = pow(self.w[j], hi*pv, self.N)
        self.x[i] = v
        return True

    def proof(self, i: int, x: str) -> int:
        p = self.H(i, x)
        return pow(self.w[i], p, self.N)

    def is_member(self, i, x) -> bool:
        if self.x[i] != x:
            return False
        proof = self.proof(i, x)
        return proof == self.alpha


if __name__ == "__main__":
    primes = []
    with open("primes.txt", "r") as f:
        primes = [int(p) for p in f.readline().split("\n")[0].split(",")]
    assert len(primes) == 1000, f"expected 1000 primes, got {len(primes)}"
    for p in primes:
        assert is_prime(p), f"expected {p} to be prime"

    p = hash_to_prime("hello", 128)
    q = hash_to_prime("world", 128)
    r = hash_to_prime("hello", 128)

    assert is_prime(p), f"expected {p} to be prime"
    assert is_prime(q), f"expected {q} to be prime"
    assert is_prime(r), f"expected {r} to be prime"
    assert p != q, f"expected {p} != {q}"
    assert p == r, f"expected {p} == {r}"

    p = 54063578048409176568533461320397553485
    q = 47877612267730623898736480941623668309
    s = 128
    acc = Accumulator(n=10, p=p, q=q, security=s)
    assert acc.is_member(5,
                         "hello") == False, f"expected acc.is_member('hello') to be False"
    success = acc.update(0, "hello")
    assert success == True, f"expected acc.update('hello') to be True"
    assert acc.is_member(0,
                         "hello") == True, f"expected acc.is_member('hello') to be True"
    success = acc.update(0, "hello")
    assert success == False, f"expected acc.update('hello') to be False"
    assert acc.is_member(0,
                         "hello") == True, f"expected acc.is_member('hello') to be True"
    success = acc.update(1, "world")
    assert success == True, f"expected acc.update('world') to be True"
    assert acc.is_member(1,
                         "world") == True, f"expected acc.is_member('world') to be True"

    success = acc.update(2, "!")
    assert success == True, f"expected acc.update('!') to be True"
    assert acc.is_member(2,
                         "!") == True, f"expected acc.is_member('!') to be True"

    print("All tests passed!")
