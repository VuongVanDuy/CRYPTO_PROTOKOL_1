"""Key data class and RSA key generation."""
from dataclasses import dataclass
from typing import Optional
from .mathops import genPrime, modinv
from .pem import savePrivateKeyPem, savePublicKeyPem

@dataclass
class RsaKeyPair:
    """Container for RSA key components and CRT parameters."""
    n: Optional[int] = None  # modulus (n = p * q)
    e: Optional[int] = None  # public exponent
    d: Optional[int] = None  # private exponent d = e^-1 mod (p-1)(q-1)

    def to_private_pem(self) -> str:
        return savePrivateKeyPem(self.n, self.d)

    def to_public_pem(self) -> str:
        return savePublicKeyPem(self.n, self.e)

def generateKeyPair(bits: int = 2048, e: int = 65537) -> RsaKeyPair | None:
    """Generate an RSA key pair of the given size.
    - bits: modulus size in bits (≥1024 recommended 2048+)
    - e: public exponent (65537 default)"""
    if bits < 1024:
        raise ValueError("Key size should be >= 1024 bits for security.")
    half = bits // 2
    while True:
        p = genPrime(half)
        q = genPrime(bits - half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = modinv(e, phi)
        return RsaKeyPair(n=n, e=e, d=d)
