import argparse
import sys
from . import DesCipherFile

def main():
    parser = argparse.ArgumentParser(
        description="DES (ECB/CBC) encryption/decryption using command-line file paths.\n"
                    "[DES (ECB/CBC) шифрование/расшифровка с использованием путей к файлам в командной строке.]"
    )
    parser.add_argument("--file", "-f", required=True,
                        help="Input file path: plaintext (for encryption) or HEX ciphertext (for decryption).\n"
                             "[Путь к входному файлу: обычный текст (для шифрования) или HEX-шифртекст (для расшифровки).]")
    parser.add_argument("--key", "-k", required=True,
                        help="Key file path (16 hex characters = 8 bytes).\n"
                             "[Путь к файлу ключа (16 шестнадцатеричных символов = 8 байт).]")
    parser.add_argument("--iv", "-i", default=None,
                        help="IV file path (16 hex characters = 8 bytes). Required for CBC mode.\n"
                             "[Путь к файлу IV (16 шестнадцатеричных символов = 8 байт). Обязательно для режима CBC.]")
    parser.add_argument("--mode", "-m", choices=["ECB", "CBC"], default="ECB",
                        help="DES mode (default: ECB). Options: ECB or CBC.\n\n"
                             "[Режим DES (по умолчанию: ECB). Варианты: ECB или CBC.]")
    parser.add_argument("--encrypt", "-e", action="store_true",
                        help="Enable to ENCRYPT. If omitted, the program will DECRYPT.\n"
                             "[Включите для ШИФРОВАНИЯ. Если не указано, программа будет РАСШИФРОВЫВАТЬ.]")
    parser.add_argument("--output", "-o", default=None,
                        help="Output file path. Encryption: saves HEX ciphertext. "
                             "Decryption: saves UTF-8 plaintext. If omitted, result is printed.\n"
                             "[Путь к выходному файлу. Шифрование: сохраняет HEX-шифртекст. "
                             "Расшифровка: сохраняет UTF-8 текст. Если не указано, результат печатается на экран.]")
    args = parser.parse_args()

    try:
        des = DesCipherFile(args.file, args.key, args.iv)
        hex_blocks, result = des.generate(
            output_file_path=args.output,
            mode=args.mode,
            encrypt=args.encrypt
        )

        if args.encrypt:
            print("[*] Mode:", args.mode)
            print("[*] Encrypted (hex blocks):", hex_blocks)
            print("[*] Encrypted (hex concat) :", result)
            if args.output:
                print(f"[*] Ciphertext saved to: {args.output}")
        else:
            print("[*] Mode:", args.mode)
            print("[*] Decrypted (blocks of plain in hex view):", hex_blocks)
            print("[*] Decrypted (plaintext):")
            print(result)
            if args.output:
                print(f"[*] Plaintext saved to: {args.output}")

    except Exception as ex:
        print("Error:", ex, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
