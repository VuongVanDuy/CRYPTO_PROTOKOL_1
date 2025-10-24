def rotr(x: int, n: int) -> int:
    return ((x >> n) | ((x & 0xFFFFFFFF) << (32 - n))) & 0xFFFFFFFF

def shr(x: int, n: int) -> int:
    return (x >> n) & 0xFFFFFFFF

def ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & z)

def maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)

def bigSigma0(x: int) -> int:
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def bigSigma1(x: int) -> int:
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def smallSigma0(x: int) -> int:
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def smallSigma1(x: int) -> int:
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)
