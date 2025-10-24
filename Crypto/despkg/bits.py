from typing import List

def bytes_to_bits(b: bytes) -> List[int]:
    return [(byte >> (7 - i)) & 1 for byte in b for i in range(8)]

def bits_to_bytes(bits: List[int]) -> bytes:
    assert len(bits) % 8 == 0
    out = bytearray()
    for i in range(0, len(bits), 8):
        val = 0
        for j in range(8):
            val = (val << 1) | bits[i + j]
        out.append(val)
    return bytes(out)

def permute(bits: List[int], table: List[int]) -> List[int]:
    return [bits[i - 1] for i in table]

def left_shift(bits: List[int], n: int) -> List[int]:
    n %= len(bits)
    return bits[n:] + bits[:n]

def int_to_bits(x: int, length: int) -> List[int]:
    return [(x >> (length - 1 - i)) & 1 for i in range(length)]

def xor_bits(a: List[int], b: List[int]) -> List[int]:
    return [i ^ j for i, j in zip(a, b)]

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid PKCS#7 input length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def hex_to_bytes_clean(s: str) -> bytes:
    s = s.strip().replace(" ", "")
    return bytes.fromhex(s)

def bytes_to_hex_spaced(b: bytes) -> str:
    return " ".join(b[i:i+8].hex() for i in range(0, len(b), 8))
