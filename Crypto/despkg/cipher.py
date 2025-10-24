from typing import Optional, Tuple
from dataclasses import dataclass
from .bits import hex_to_bytes_clean
from .block import generate_subkeys_from_key64
from .modes import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt

class DesCipherFile:
    def __init__(self, path_file: str, path_key: str, path_iv: Optional[str] = None) -> None:
        self.path_file = path_file
        self.path_key = path_key
        self.path_iv = path_iv

    @staticmethod
    def _load_key_bits(path_key: str):
        with open(path_key, "r", encoding="utf-8") as f:
            key_hex = f.read().strip()
        key = hex_to_bytes_clean(key_hex)
        if len(key) != 8:
            raise ValueError("DES key must be 8 bytes (16 hex chars).")
        # chuyển sang bit mảng:
        return [ (byte >> (7 - i)) & 1 for byte in key for i in range(8) ]

    def generate(self, output_file_path: Optional[str], mode: str = "ECB", encrypt: bool = True) -> Tuple[str, str]:
        with open(self.path_file, "r", encoding="utf-8") as f:
            content = f.read()

        # Chuẩn hóa input: encrypt => plaintext UTF-8; decrypt => hex ciphertext
        if encrypt:
            msg_bytes = content.encode("utf-8")
        else:
            try:
                msg_bytes = bytes.fromhex(content.strip().replace(" ", ""))
            except Exception:
                # fallback nếu file không phải hex (ít dùng)
                msg_bytes = content.encode("utf-8")

        key_bits = self._load_key_bits(self.path_key)
        subkeys = generate_subkeys_from_key64(key_bits)

        if mode.upper() == "ECB":
            if encrypt:
                hex_blocks, cipher = ecb_encrypt(msg_bytes, subkeys)
                if output_file_path:
                    with open(output_file_path, "w", encoding="utf-8") as f:
                        f.write(cipher.hex())
                return hex_blocks, cipher.hex()
            else:
                hex_blocks, plain = ecb_decrypt(msg_bytes, subkeys)
                if output_file_path:
                    with open(output_file_path, "w", encoding="utf-8") as f:
                        f.write(plain.decode("utf-8"))
                return hex_blocks, plain.decode("utf-8")

        elif mode.upper() == "CBC":
            if not self.path_iv:
                raise ValueError("IV file is required for CBC mode.")
            with open(self.path_iv, "r", encoding="utf-8") as f:
                iv = hex_to_bytes_clean(f.read().strip())

            if encrypt:
                hex_blocks, cipher = cbc_encrypt(msg_bytes, subkeys, iv)
                if output_file_path:
                    with open(output_file_path, "w", encoding="utf-8") as f:
                        f.write(cipher.hex())
                return hex_blocks, cipher.hex()
            else:
                hex_blocks, plain = cbc_decrypt(msg_bytes, subkeys, iv)
                if output_file_path:
                    with open(output_file_path, "w", encoding="utf-8") as f:
                        f.write(plain.decode("utf-8"))
                return hex_blocks, plain.decode("utf-8")
        else:
            raise ValueError("Unsupported mode. Use 'ECB' or 'CBC'.")

class DesCipher:
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, iv: Optional[bytes] = None, mode: str = "ECB") -> bytes:
        key_bits = [ (byte >> (7 - i)) & 1 for byte in key for i in range(8) ]
        subkeys = generate_subkeys_from_key64(key_bits)

        if mode.upper() == "ECB":
            _, cipher = ecb_encrypt(plaintext, subkeys)
            return cipher
        elif mode.upper() == "CBC":
            if iv is None:
                raise ValueError("IV is required for CBC mode.")
            _, cipher = cbc_encrypt(plaintext, subkeys, iv)
            return cipher
        else:
            raise ValueError("Unsupported mode. Use 'ECB' or 'CBC'.")

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, iv: Optional[bytes] = None, mode: str = "ECB") -> bytes:
        key_bits = [ (byte >> (7 - i)) & 1 for byte in key for i in range(8) ]
        subkeys = generate_subkeys_from_key64(key_bits)

        if mode.upper() == "ECB":
            _, plain = ecb_decrypt(ciphertext, subkeys)
            return plain
        elif mode.upper() == "CBC":
            if iv is None:
                raise ValueError("IV is required for CBC mode.")
            _, plain = cbc_decrypt(ciphertext, subkeys, iv)
            return plain
        else:
            raise ValueError("Unsupported mode. Use 'ECB' or 'CBC'.")
