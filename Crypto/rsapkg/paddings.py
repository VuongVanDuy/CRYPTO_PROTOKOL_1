"""
RSA padding primitives (OAEP, PKCS#1 v1.5, PSS)
Implemented using our pure-Python SHA256 class (sha256pkg.Sha256).
"""

import secrets
from .utils import ceilDiv
from Crypto.sha256pkg import Sha256


def mgf1(seed: bytes, length: int) -> bytes:
    """MGF1 mask generation using our SHA256 implementation.
    Args:
        seed: seed bytes
        length: number of bytes to generate
    Returns:
        A mask of `length` bytes derived from the seed.
    """
    hlen = 32  # SHA256 digest size
    T = bytearray()
    for counter in range(ceilDiv(length, hlen)):
        C = counter.to_bytes(4, "big")
        T.extend(Sha256.hash(seed + C))
    return bytes(T[:length])


# ---------------- RSAES-OAEP ----------------
def oaepEncode(message: bytes, k: int, label: bytes = b"") -> bytes:
    """Encode message using OAEP and SHA256.
    Args:
        message: plaintext to encode
        k: modulus length in bytes
        label: optional label (default empty)
    Returns:
        Encoded message block ready for RSA encryption.
    """
    h = Sha256.hash(label)
    hlen = len(h)
    mlen = len(message)
    if mlen > k - 2 * hlen - 2:
        raise ValueError("message too long for OAEP")
    PS = b"\x00" * (k - mlen - 2 * hlen - 2)
    DB = h + PS + b"\x01" + message
    seed = secrets.token_bytes(hlen)
    dbMask = mgf1(seed, k - hlen - 1)
    maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))
    seedMask = mgf1(maskedDB, hlen)
    maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))
    return b"\x00" + maskedSeed + maskedDB


def oaepDecode(EM: bytes, k: int, label: bytes = b"") -> bytes:
    """Decode OAEP-encoded message using SHA256.
    Args:
        EM: encoded message block (k bytes)
        k: modulus length in bytes
        label: optional label (default empty)
    Returns:
        The recovered plaintext.
    Raises:
        ValueError: if the padding is invalid.
    """
    h = Sha256.hash(label)
    hlen = len(h)
    if len(EM) != k or k < 2 * hlen + 2:
        raise ValueError("decryption error")
    Y = EM[0]
    maskedSeed = EM[1:1 + hlen]
    maskedDB = EM[1 + hlen:]
    seedMask = mgf1(maskedDB, hlen)
    seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))
    dbMask = mgf1(seed, k - hlen - 1)
    DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))
    lhash = DB[:hlen]
    if Y != 0 or lhash != h:
        raise ValueError("decryption error")
    idx = DB.find(b"\x01", hlen)
    if idx == -1:
        raise ValueError("decryption error")
    return DB[idx + 1:]


# --------------- PKCS#1 v1.5 (legacy) ---------------
def pkcs1v15Pad(message: bytes, k: int) -> bytes:
    """Add PKCS#1 v1.5 encryption padding.
    Format: 0x00 || 0x02 || PS (non-zero random) || 0x00 || M
    """
    ps_len = k - len(message) - 3
    if ps_len < 8:
        raise ValueError("message too long")
    PS = bytearray()
    while len(PS) < ps_len:
        b = secrets.randbelow(255) + 1
        PS.append(b)
    return b"\x00\x02" + bytes(PS) + b"\x00" + message


def pkcs1v15Unpad(EM: bytes) -> bytes:
    """Remove PKCS#1 v1.5 encryption padding."""
    if len(EM) < 11 or EM[0] != 0x00 or EM[1] != 0x02:
        raise ValueError("decryption error")
    sep = EM.find(b"\x00", 2)
    if sep == -1 or sep < 10:
        raise ValueError("decryption error")
    return EM[sep + 1:]


# ---------------- RSASSA-PSS ----------------
def pssEncode(message: bytes, emBits: int, saltLen: int = 32) -> bytes:
    """Encode message for PSS signature using SHA256.
    Args:
        message: original message
        emBits: number of bits of the RSA modulus - 1
        saltLen: length of random salt (default 32)
    Returns:
        Encoded message block ready for RSA signing.
    """
    hlen = 32
    emLen = ceilDiv(emBits, 8)
    if emLen < hlen + saltLen + 2:
        raise ValueError("encoding error")
    mHash =  Sha256.hash(message)
    salt = secrets.token_bytes(saltLen)
    M = b"\x00" * 8 + mHash + salt
    Hm = Sha256.hash(M)
    PS = b"\x00" * (emLen - saltLen - hlen - 2)
    DB = PS + b"\x01" + salt
    dbMask = mgf1(Hm, emLen - hlen - 1)
    maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))
    unused = 8 * emLen - emBits
    if unused:
        maskedDB = bytes([maskedDB[0] & (0xFF >> unused)]) + maskedDB[1:]
    return maskedDB + Hm + b"\xbc"

def pssVerify(message: bytes, EM: bytes, emBits: int, saltLen: int = 32) -> bool:
    """Verify PSS-encoded block using SHA256.
        Args:
            message: original message
            EM: encoded block to verify
            emBits: modulus bit length - 1
            saltLen: expected salt length
        Returns:
            True if verification passes, False otherwise.
        """
    hlen = 32
    emLen = ceilDiv(emBits, 8)
    if emLen < hlen + saltLen + 2 or len(EM) != emLen or EM[-1] != 0xbc:
        return False

    maskedDB = EM[:emLen - hlen - 1]
    Hm = EM[emLen - hlen - 1:-1]

    unused = 8 * emLen - emBits
    if unused and (maskedDB[0] & (~(0xFF >> unused))) != 0:
        return False

    dbMask = mgf1(Hm, emLen - hlen - 1)
    DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))
    if unused:
        DB = bytes([DB[0] & (0xFF >> unused)]) + DB[1:]

    # ✅ Xác định đúng vị trí theo chuẩn
    ps_len = emLen - hlen - saltLen - 2
    if ps_len < 0:
        return False
    if DB[:ps_len] != b"\x00" * ps_len:
        return False
    if DB[ps_len] != 0x01:
        return False
    salt = DB[ps_len + 1 : ps_len + 1 + saltLen]
    if len(salt) != saltLen:
        return False

    mHash = Sha256.hash(message)
    M = b"\x00" * 8 + mHash + salt
    Hm2 = Sha256.hash(M)
    return Hm == Hm2

