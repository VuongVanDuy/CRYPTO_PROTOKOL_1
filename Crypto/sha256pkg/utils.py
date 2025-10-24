def intToHex(value: int, width: int | None = None, spaced: bool = False) -> str:
    """
    Convert int to hex string (lowercase). If width is given, pad to that many hex digits.
    If spaced=True, insert a space every two hex characters.
    """
    if value < 0:
        raise ValueError("value must be non-negative")
    hexstr = format(value, 'x')
    if width is not None and width > len(hexstr):
        hexstr = hexstr.zfill(width)
    if spaced:
        return ' '.join(hexstr[i:i+2] for i in range(0, len(hexstr), 2))
    return hexstr

def hexToInt(hexString: str) -> int:
    """Convert hex string (spaces allowed) to int."""
    return int(hexString.replace(' ', ''), 16)
