from dataclasses import dataclass
from typing import Optional
from .keys import RsaKeyPair, generateKeyPair
from .pem import savePrivateKeyPem, loadPrivateKeyPem, savePublicKeyPem, loadPublicKeyPem
from .rsa_core import rsaEncrypt, rsaDecrypt, rsaSign, rsaVerify

@dataclass
class Rsa:
    """High-level RSA class context (public-only or full keypair)."""
    n: Optional[int] = None # modulus (n = p * q)
    e: Optional[int] = None # public exponent
    d: Optional[int] = None # private exponent d = e^-1 mod (p-1)(q-1)

    @staticmethod
    def generate(bits: int = 2048, e: int = 65537) -> "Rsa":
        kp = generateKeyPair(bits=bits, e=e)
        return Rsa(n=kp.n, e=kp.e, d=kp.d)

    @staticmethod
    def from_private_pem(pem: str) -> "Rsa":
        n, d = loadPrivateKeyPem(pem)
        return Rsa(n=n, d=d)

    @staticmethod
    def from_public_pem(pem: str) -> "Rsa":
        n, e = loadPublicKeyPem(pem)
        return Rsa(n=n, e=e)

    def to_private_pem(self) -> str:
        return savePrivateKeyPem(self.n, self.d)

    def to_public_pem(self) -> str:
        return savePublicKeyPem(self.n, self.e)

    def encrypt(self, plaintext: bytes, padding: str = "oaep") -> bytes:
        return rsaEncrypt(plaintext, self.n, self.e, padding=padding)

    def decrypt(self, ciphertext: bytes, padding: str = "oaep") -> bytes:
        if self.d is None:
            raise ValueError("Private key required for decryption")
        return rsaDecrypt(ciphertext, self.n, self.d, padding=padding)

    def sign(self, message: bytes, padding: str = "pss") -> bytes:
        if self.d is None:
            raise ValueError("Private key required for signing")
        return rsaSign(message, self.n, self.d, padding=padding)

    def verify(self, message: bytes, signature: bytes, padding: str = "pss") -> bool:
        return rsaVerify(message, signature, self.n, self.e, padding=padding)
