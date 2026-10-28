#!/usr/bin/env python3
"""Checks that a codesigned macOS binary is an unsigned build plus a signature.

Usage:  scripts/compare-signed.py SIGNED UNSIGNED

Both files have their signature removed. codesign leaves the __LINKEDIT
segment's vmsize page-aligned when it removes a signature, so that one field is
zeroed in both. Everything else must match byte for byte. Needs macOS.
"""

import hashlib
import shutil
import struct
import subprocess
import sys
import tempfile

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19


def normalized(path: str) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        copy = f"{tmp}/bin"
        shutil.copyfile(path, copy)
        subprocess.run(["codesign", "--remove-signature", copy], check=True)
        with open(copy, "rb") as f:
            data = bytearray(f.read())

    (magic,) = struct.unpack_from("<I", data, 0)
    if magic != MH_MAGIC_64:
        sys.exit(f"{path}: not a 64-bit Mach-O")
    (ncmds,) = struct.unpack_from("<I", data, 16)
    offset = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, offset)
        name = bytes(data[offset + 8 : offset + 24]).rstrip(b"\0")
        if cmd == LC_SEGMENT_64 and name == b"__LINKEDIT":
            struct.pack_into("<Q", data, offset + 32, 0)
        offset += size
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    signed, unsigned = normalized(sys.argv[1]), normalized(sys.argv[2])
    if signed != unsigned:
        sys.exit(f"differ beyond the signature:\n  {signed}\n  {unsigned}")
    print(f"same code: {signed}")


if __name__ == "__main__":
    main()
