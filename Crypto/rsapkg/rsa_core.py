"""High-level RSA operations: encrypt/decrypt and sign/verify."""
from .utils import i2osp, os2ip
from .paddings import oaepEncode, oaepDecode, pkcs1v15Pad, pkcs1v15Unpad, pssEncode, pssVerify

def rsaEncrypt(m: bytes, n: int, e: int, padding: str = "oaep") -> bytes:
    """Encrypt message m using public key (n, e).
    - padding: 'oaep' (default), 'pkcs1v15', or 'raw' (no padding)."""
    k = (n.bit_length() + 7) // 8
    if padding == "oaep":
        em = oaepEncode(m, k)
    elif padding == "pkcs1v15":
        em = pkcs1v15Pad(m, k)
    elif padding == "raw":
        em = m
        if len(em) > k:
            raise ValueError("message too long")
    else:
        raise ValueError("unknown padding")
    c = pow(os2ip(em), e, n)
    return i2osp(c, k)

def rsaDecrypt(c: bytes, n: int, d: int, padding: str = "oaep") -> bytes:
    """Decrypt ciphertext c using private exponent d and modulus n."""
    k = (n.bit_length() + 7) // 8
    m = pow(os2ip(c), d, n)
    em = i2osp(m, k)
    if padding == "oaep":
        return oaepDecode(em, k)
    elif padding == "pkcs1v15":
        return pkcs1v15Unpad(em)
    elif padding == "raw":
        return em
    else:
        raise ValueError("unknown padding")

def rsaSign(message: bytes, n: int, d: int, padding: str = "pss") -> bytes:
    """Create a signature on message using private exponent d (default PSS)."""
    k = (n.bit_length() + 7) // 8
    if padding == "pss":
        em = pssEncode(message, n.bit_length() - 1)
    elif padding == "raw":
        em = message
        if len(em) > k:
            raise ValueError("message too long")
    else:
        raise ValueError("unknown padding")
    s = pow(os2ip(em), d, n)
    return i2osp(s, k)

def rsaVerify(message: bytes, signature: bytes, n: int, e: int, padding: str = "pss") -> bool:
    """Verify a signature with public key (n, e). Returns True/False."""
    k = (n.bit_length() + 7) // 8
    s = os2ip(signature)
    em = i2osp(pow(s, e, n), k)
    if padding == "pss":
        return pssVerify(message, em, n.bit_length() - 1)
    elif padding == "raw":
        return em == message
    else:
        raise ValueError("unknown padding")
