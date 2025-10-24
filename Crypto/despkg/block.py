from typing import List
from .tables import IP, FP, E, P, PC1, PC2, SBOXES, SHIFT_SCHEDULE
from .bits import bytes_to_bits, bits_to_bytes, permute, left_shift, int_to_bits, xor_bits

def sbox_substitution(bits48: List[int]) -> List[int]:
    out: List[int] = []
    for i in range(8):
        block = bits48[i*6:(i+1)*6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = SBOXES[i][row][col]
        out.extend(int_to_bits(val, 4))
    return out

def f_function(right32: List[int], subkey48: List[int]) -> List[int]:
    expanded = permute(right32, E)
    xored = xor_bits(expanded, subkey48)
    sboxed = sbox_substitution(xored)
    return permute(sboxed, P)

def generate_subkeys_from_key64(key64_bits: List[int]) -> List[List[int]]:
    key56 = permute(key64_bits, PC1)
    C, D = key56[:28], key56[28:]
    subkeys = []
    for shift in SHIFT_SCHEDULE:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        subkeys.append(permute(C + D, PC2))
    return subkeys

def des_block_encrypt(block8: bytes, subkeys: List[List[int]]) -> bytes:
    bits = bytes_to_bits(block8)
    bits = permute(bits, IP)
    L, R = bits[:32], bits[32:]
    for k in subkeys:
        L, R = R, xor_bits(L, f_function(R, k))
    pre_output = R + L
    out_bits = permute(pre_output, FP)
    return bits_to_bytes(out_bits)

def des_block_decrypt(block8: bytes, subkeys: List[List[int]]) -> bytes:
    bits = bytes_to_bits(block8)
    bits = permute(bits, IP)
    L, R = bits[:32], bits[32:]
    for k in reversed(subkeys):
        L, R = R, xor_bits(L, f_function(R, k))
    pre_output = R + L
    out_bits = permute(pre_output, FP)
    return bits_to_bytes(out_bits)
