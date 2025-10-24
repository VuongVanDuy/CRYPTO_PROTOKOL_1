"""Utility helpers for integer/byte conversions used across RSA."""
import math

def intToHex(value: int, width: int | None = None, spaced: bool = False) -> str:
    """Convert a non-negative integer to a lowercase hex string.
    - width: pad with zeros to this many hex digits (optional).
    - spaced: insert spaces every 2 hex chars (byte grouping).
    """
    if value < 0:
        raise ValueError("value must be non-negative")
    hexstr = format(value, 'x')
    if width is not None and width > len(hexstr):
        hexstr = hexstr.zfill(width)
    return ' '.join(hexstr[i:i+2] for i in range(0, len(hexstr), 2)) if spaced else hexstr

def hexToInt(hexString: str) -> int:
    """Parse a hex string (spaces allowed) into an integer."""
    return int(hexString.replace(' ', ''), 16)

def i2osp(x: int, xLen: int) -> bytes:
    """Integer-to-Octet-String primitive (RFC 8017): fixed-length big-endian."""
    if x < 0 or x >= 256**xLen:
        raise ValueError("integer too large")
    return x.to_bytes(xLen, 'big')

def os2ip(x: bytes) -> int:
    """Octet-String-to-Integer primitive (RFC 8017): big-endian parse."""
    return int.from_bytes(x, 'big')

def ceilDiv(a: int, b: int) -> int:
    """Ceiling division helper."""
    return -(-a // b)
