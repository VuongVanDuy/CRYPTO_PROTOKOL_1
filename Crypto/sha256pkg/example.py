from . import Sha256
from .utils import intToHex, hexToInt

def main():
    print("Test vectors:")
    tests = {
        "": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "hello world": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    }
    for msg, expect in tests.items():
        got = Sha256.hashHex(msg)
        print(f"{msg!r} -> {got} | {'OK' if got == expect else 'FAIL'}")

    # int <-> hex helpers
    n = 305419896  # 0x12345678
    hx = intToHex(n, width=8, spaced=True)
    back = hexToInt(hx)
    print("int->hex:", hx, "| hex->int:", back)

if __name__ == "__main__":
    main()
