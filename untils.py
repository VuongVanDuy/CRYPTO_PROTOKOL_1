import json, base64, textwrap, os

def _wrap_pem(b64: str, header: str, footer: str) -> str:
    """Wrap a base64 string with BEGIN/END headers for readability."""
    body = "\n".join(textwrap.wrap(b64, 64))
    return f"{header}\n{body}\n{footer}\n"

def decode_pem(pem: str) -> dict:
    """Parse a certificate from our simple PEM format back to dict."""
    lines = [ln.strip() for ln in pem.strip().splitlines() if not ln.startswith("-----")]
    data = base64.b64decode("".join(lines))
    return json.loads(data.decode("utf-8"))

def loadCertPublicKeyPem(pem: str) -> tuple[tuple[int, int], tuple[int, int]]:
    """Parse a public key (n, e) from our simple PEM format."""
    cert_pem = decode_pem(pem)
    subj_key_en = cert_pem["tbs"]["subject_key_encrypt"]
    n1 = subj_key_en["n"]
    e1 = subj_key_en["e"]
    subj_key_sign = cert_pem["tbs"]["subject_key_sign"]
    n2 = subj_key_sign["n"]
    e2 = subj_key_sign["e"]
    return (n1, e1), (n2, e2)

def load_key_from_file(file_path: str) -> str | None:
    """Đọc nội dung khóa PEM từ file."""
    # check file existence
    if not os.path.exists(file_path):
        return None
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()

def save_key_to_file(file_path: str, pem_data: str) -> str | None:
    """Lưu nội dung khóa PEM vào file."""
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(pem_data)
        return file_path
    except Exception as e:
        print(f"Error saving key to file: {e}")
        return None

def format_valid_pem(pem: str, header: str, footer: str) -> str:
    """Định dạng lại PEM với header và footer đúng chuẩn."""
    lines = [ln.strip() for ln in pem.strip().splitlines() if not ln.startswith("-----")]
    b64 = "".join(lines)
    return _wrap_pem(b64, header, footer)


def format_pem(pem: str) -> str:
    pem_single_line = pem.replace("\r\n", "\n")
    return pem_single_line

if __name__ == "__main__":
    # Example usage
    pem_path = "data/keys/alice_public.pem"
    with open(pem_path, "r", encoding="utf-8") as f:
        pem_data = f.read()
    pem_single_line = format_pem(pem_data)
    print(pem_single_line)
