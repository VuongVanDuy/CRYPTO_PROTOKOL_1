import argparse, sys, base64
from . import Rsa

def read_file(path: str, binary: bool = True) -> bytes:
    mode = "rb" if binary else "r"
    with open(path, mode) as f:
        return f.read() if binary else f.read().encode("utf-8")

def write_file(path: str, data: bytes, binary: bool = True):
    mode = "wb" if binary else "w"
    with open(path, mode) as f:
        f.write(data if binary else data.decode("utf-8"))

def cmd_genkey(args):
    ctx = Rsa.generate(bits=args.bits, e=args.e)
    priv_pem = ctx.to_private_pem()
    pub_pem = ctx.to_public_pem()
    if args.private:
        write_file(args.private, priv_pem.encode("utf-8"), binary=True)
        print(f"Private key saved to: {args.private}")
    else:
        print(priv_pem)
    if args.public:
        write_file(args.public, pub_pem.encode("utf-8"), binary=True)
        print(f"Public key saved to: {args.public}")
    else:
        print(pub_pem)

def cmd_encrypt(args):
    ctx = Rsa.from_public_pem(read_file(args.pub, binary=False).decode("utf-8"))
    data = read_file(args.input, binary=True)
    ct = ctx.encrypt(data, padding=args.padding)
    out = base64.b64encode(ct) if args.base64 else ct
    if args.output:
        write_file(args.output, out, binary=True)
        print(f"Ciphertext written to: {args.output}")
    else:
        if args.base64:
            print(out.decode("ascii"))
        else:
            sys.stdout.buffer.write(out)

def cmd_decrypt(args):
    ctx = Rsa.from_private_pem(read_file(args.priv, binary=False).decode("utf-8"))
    data = read_file(args.input, binary=True)
    if args.base64:
        data = base64.b64decode(data)
    pt = ctx.decrypt(data, padding=args.padding)
    if args.output:
        write_file(args.output, pt, binary=True)
        print(f"Plaintext written to: {args.output}")
    else:
        sys.stdout.buffer.write(pt)

def cmd_sign(args):
    ctx = Rsa.from_private_pem(read_file(args.priv, binary=False).decode("utf-8"))
    msg = read_file(args.input, binary=True)
    sig = ctx.sign(msg, padding=args.padding)
    out = base64.b64encode(sig) if args.base64 else sig
    if args.output:
        write_file(args.output, out, binary=True)
        print(f"Signature written to: {args.output}")
    else:
        if args.base64:
            print(out.decode("ascii"))
        else:
            sys.stdout.buffer.write(out)

def cmd_verify(args):
    ctx = Rsa.from_public_pem(read_file(args.pub, binary=False).decode("utf-8"))
    msg = read_file(args.input, binary=True)
    sig = read_file(args.signature, binary=True)
    if args.base64:
        sig = base64.b64decode(sig)
    ok = ctx.verify(msg, sig, padding=args.padding)
    print("OK" if ok else "FAIL")
    sys.exit(0 if ok else 2)

def main():
    parser = argparse.ArgumentParser(
        prog="rsacli",
        description="Educational RSA tool (class-based). Defaults: OAEP for encryption, PSS for signatures."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("genkey", help="Generate RSA key pair")
    p_gen.add_argument("--bits", type=int, default=2048, help="Key size in bits (default: 2048)")
    p_gen.add_argument("-e", type=int, default=65537, help="Public exponent (default: 65537)")
    p_gen.add_argument("--private", help="Output file for private key PEM")
    p_gen.add_argument("--public", help="Output file for public key PEM")
    p_gen.set_defaults(func=cmd_genkey)

    p_enc = sub.add_parser("encrypt", help="Encrypt with public key")
    p_enc.add_argument("--pub", required=True, help="Public key PEM file")
    p_enc.add_argument("-i", "--input", required=True, help="Input file (plaintext)")
    p_enc.add_argument("-o", "--output", help="Output file (ciphertext)")
    p_enc.add_argument("--padding", choices=["oaep", "pkcs1v15", "raw"], default="oaep", help="Padding scheme")
    p_enc.add_argument("--base64", action="store_true", help="Base64 encode output")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Decrypt with private key")
    p_dec.add_argument("--priv", required=True, help="Private key PEM file")
    p_dec.add_argument("-i", "--input", required=True, help="Input file (ciphertext)")
    p_dec.add_argument("-o", "--output", help="Output file (plaintext)")
    p_dec.add_argument("--padding", choices=["oaep", "pkcs1v15", "raw"], default="oaep", help="Padding scheme")
    p_dec.add_argument("--base64", action="store_true", help="Input ciphertext is base64-encoded")
    p_dec.set_defaults(func=cmd_decrypt)

    p_sig = sub.add_parser("sign", help="Sign with private key")
    p_sig.add_argument("--priv", required=True, help="Private key PEM file")
    p_sig.add_argument("-i", "--input", required=True, help="Input file (message)")
    p_sig.add_argument("-o", "--output", help="Output file (signature)")
    p_sig.add_argument("--padding", choices=["pss", "raw"], default="pss", help="Signature scheme")
    p_sig.add_argument("--base64", action="store_true", help="Base64 encode output signature")
    p_sig.set_defaults(func=cmd_sign)

    p_ver = sub.add_parser("verify", help="Verify signature with public key")
    p_ver.add_argument("--pub", required=True, help="Public key PEM file")
    p_ver.add_argument("-i", "--input", required=True, help="Input file (message)")
    p_ver.add_argument("--signature", required=True, help="Signature file")
    p_ver.add_argument("--padding", choices=["pss", "raw"], default="pss", help="Signature scheme")
    p_ver.add_argument("--base64", action="store_true", help="Signature file is base64-encoded")
    p_ver.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
