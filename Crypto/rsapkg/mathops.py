"""Basic number-theory helpers for RSA: modular inverse and prime generation."""
import secrets

def egcd(a: int, b: int):
    """Extended Euclidean Algorithm.
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, n: int) -> int:
    """Compute modular inverse of a modulo n (a^{-1} mod n)."""
    g, x, y = egcd(a, n)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % n

def isProbablePrime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29,31,37]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        skip = False
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                skip = True
                break
        if skip:
            continue
        return False
    return True

def genPrime(bits: int) -> int:
    """Generate a random probable prime of the given bit length."""
    if bits < 16:
        raise ValueError("bits too small")
    while True:
        cand = secrets.randbits(bits) | 1
        cand |= (1 << (bits - 1))
        if isProbablePrime(cand):
            return cand

if __name__ == "__main__":
    # Simple test
    prime = genPrime(20)
    print(f"Generated prime: {prime}")