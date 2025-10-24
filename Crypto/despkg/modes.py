from typing import List, Tuple
from .bits import pkcs7_pad, pkcs7_unpad, bytes_to_hex_spaced
from .block import des_block_encrypt, des_block_decrypt

def ecb_encrypt(plain: bytes, subkeys: List[List[int]]) -> Tuple[str, bytes]:
    data = pkcs7_pad(plain, 8)
    out = bytearray()
    for i in range(0, len(data), 8):
        out += des_block_encrypt(data[i:i+8], subkeys)
    return bytes_to_hex_spaced(bytes(out)), bytes(out)

def ecb_decrypt(cipher: bytes, subkeys: List[List[int]]) -> Tuple[str, bytes]:
    if len(cipher) % 8 != 0:
        raise ValueError("Ciphertext length must be multiple of 8")
    out = bytearray()
    for i in range(0, len(cipher), 8):
        out += des_block_decrypt(cipher[i:i+8], subkeys)
    plain = pkcs7_unpad(bytes(out), 8)
    return bytes_to_hex_spaced(plain), plain

def cbc_encrypt(plain: bytes, subkeys: List[List[int]], iv: bytes) -> Tuple[str, bytes]:
    if len(iv) != 8:
        raise ValueError("IV must be 8 bytes")
    data = pkcs7_pad(plain, 8)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 8):
        block = bytes(a ^ b for a, b in zip(data[i:i+8], prev))
        enc = des_block_encrypt(block, subkeys)
        out += enc
        prev = enc
    return bytes_to_hex_spaced(bytes(out)), bytes(out)

def cbc_decrypt(cipher: bytes, subkeys: List[List[int]], iv: bytes) -> Tuple[str, bytes]:
    if len(iv) != 8:
        raise ValueError("IV must be 8 bytes")
    if len(cipher) % 8 != 0:
        raise ValueError("Ciphertext length must be multiple of 8")
    out = bytearray()
    prev = iv
    for i in range(0, len(cipher), 8):
        dec = des_block_decrypt(cipher[i:i+8], subkeys)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = cipher[i:i+8]
    plain = pkcs7_unpad(bytes(out), 8)
    return bytes_to_hex_spaced(plain), plain
