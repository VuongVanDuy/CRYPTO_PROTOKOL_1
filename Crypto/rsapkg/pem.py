"""Very simple PEM-like helpers (JSON fields hex-encoded, wrapped in Base64).
NOTE: This is NOT PKCS#1/PKCS#8/DER — for learning/demo only.
"""
import json, base64, textwrap

def _wrap_pem(b64: str, header: str, footer: str) -> str:
    """Wrap a base64 string with BEGIN/END headers for readability."""
    body = "\n".join(textwrap.wrap(b64, 64))
    return f"{header}\n{body}\n{footer}\n"

def decode_pem(pem: str) -> dict:
    """Parse a certificate from our simple PEM format back to dict."""
    lines = [ln.strip() for ln in pem.strip().splitlines() if not ln.startswith("-----")]
    data = base64.b64decode("".join(lines))
    return json.loads(data.decode("utf-8"))

def savePrivateKeyPem(n: int, d: int) -> str:
    """Serialize a private key (with CRT params) to our simple PEM format."""
    obj = {"n": format(n, "x"), "d": format(d, "x")}
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    b64 = base64.b64encode(data).decode("ascii")
    return _wrap_pem(b64, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----")

def loadPrivateKeyPem(pem: str) -> tuple[int, int]:
    """Parse a private key from our simple PEM format back to RsaKeyPair."""
    obj = decode_pem(pem)
    return int(obj["n"], 16), int(obj["d"], 16)

def savePublicKeyPem(n: int, e: int) -> str:
    """Serialize a public key (n, e) to our simple PEM format."""
    obj = {"n": format(n, "x"), "e": format(e, "x")}
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    b64 = base64.b64encode(data).decode("ascii")
    return _wrap_pem(b64, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----")

def loadPublicKeyPem(pem: str) -> tuple[int, int]:
    """Parse a public key (n, e) from our simple PEM format."""
    obj = decode_pem(pem)
    return int(obj["n"], 16), int(obj["e"], 16)
