import argparse
import sys
import os
import base64
from . import Sha256

def hash_string(data: str, raw: bool = False) -> str:
    """Compute SHA-256 hash for a string."""
    digest = Sha256.hash(data.encode("utf-8"))
    return base64.b64encode(digest).decode("utf-8") if raw else digest.hex()

def hash_file(path: str, raw: bool = False, chunk_size: int = 65536) -> str:
    """Compute SHA-256 hash for a file."""
    if not os.path.isfile(path):
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)
    digest = Sha256.hashFile(path, chunk_size)
    return base64.b64encode(digest).decode("utf-8") if raw else digest.hex()

def write_output(output_path: str, content: str):
    """Write the hash result to a file."""
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content + "\n")
        print(f"Result has been saved to: {output_path}")
    except Exception as e:
        print(f"Failed to write output file: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        prog="sha256cli",
        description="A simple SHA-256 command-line tool (pure Python, no hashlib)."
    )
    parser.add_argument("input", nargs="?", help="String or file path to hash.")
    parser.add_argument(
        "-f", "--file", action="store_true",
        help="Treat input as a file path instead of a plain string."
    )
    parser.add_argument(
        "-r", "--raw", action="store_true",
        help="Output in Base64 format instead of hexadecimal."
    )
    parser.add_argument(
        "-c", "--chunk", type=int, default=65536,
        help="Chunk size in bytes when reading a file (default: 65536)."
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Save the hash result to a file instead of printing it."
    )

    args = parser.parse_args()

    if not args.input:
        print("Please provide a string or file path to hash.", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    # Compute hash
    result = (
        hash_file(args.input, raw=args.raw, chunk_size=args.chunk)
        if args.file
        else hash_string(args.input, raw=args.raw)
    )

    # Save or print
    if args.output:
        write_output(args.output, result)
    else:
        print(result)

if __name__ == "__main__":
    main()
