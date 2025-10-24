from .bitops import smallSigma0, smallSigma1

def pad(message: bytes) -> bytes:
    ml = len(message) * 8  # message length in bits
    data = bytearray(message)
    data.append(0x80)  # append single '1' bit
    while (len(data) * 8) % 512 != 448:
        data.append(0x00)
    data += ml.to_bytes(8, byteorder="big")
    return bytes(data)

def messageSchedule(block: bytes) -> list[int]:
    # first 16 words (big-endian)
    w = [int.from_bytes(block[i:i+4], "big") for i in range(0, 64, 4)]
    # extend to 64 words
    for t in range(16, 64):
        val = (smallSigma1(w[t-2]) + w[t-7] + smallSigma0(w[t-15]) + w[t-16]) & 0xFFFFFFFF
        w.append(val)
    return w
