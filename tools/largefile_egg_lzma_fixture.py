#!/usr/bin/env python3
"""Create a minimal non-solid EGG archive with one raw-LZMA member."""

import lzma
import struct
import sys


EOFARC = 0x08E28222


def build_fixture(payload: bytes) -> bytes:
    filters = [{"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16, "lc": 3, "lp": 0, "pb": 2}]
    compressed = lzma.compress(payload, format=lzma.FORMAT_RAW, filters=filters)
    lzma_block = b"\x5d" + struct.pack("<I", 1 << 16) + struct.pack("<Q", len(payload)) + compressed

    archive = bytearray()
    archive.extend(struct.pack("<I H I I I", 0x41474745, 0x0100, 1, 0, EOFARC))
    archive.extend(struct.pack("<I I Q", 0x0A8590E3, 1, len(payload)))
    archive.extend(struct.pack("<I B H", 0x0A8591AC, 0, 8))
    archive.extend(b"test.txt")
    archive.extend(struct.pack("<I", EOFARC))
    archive.extend(struct.pack("<I B B I I I", 0x02B50C13, 4, 0,
                               len(payload), len(lzma_block), 0))
    archive.extend(struct.pack("<I", EOFARC))
    archive.extend(lzma_block)
    archive.extend(struct.pack("<I", EOFARC))
    return bytes(archive)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} OUTPUT")
    with open(sys.argv[1], "wb") as output:
        output.write(build_fixture(b"EGG LZMA stream"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
