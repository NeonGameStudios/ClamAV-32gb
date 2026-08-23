#!/usr/bin/env python3
"""Create a sparse, structurally valid BigTIFF with metadata above 4 GiB."""

import os
import struct
import sys


FIRST_IFD_OFFSET = (1 << 32) + 16
EXTERNAL_VALUE_OFFSET = FIRST_IFD_OFFSET + 40
FILE_SIZE = EXTERNAL_VALUE_OFFSET + 16


def build_fixture(path: str) -> None:
    header = b"II+\0" + struct.pack("<HHQ", 8, 0, FIRST_IFD_OFFSET)
    entry = struct.pack("<HHQQ", 256, 16, 2, EXTERNAL_VALUE_OFFSET)

    with open(path, "wb") as fixture:
        fixture.write(header)
        fixture.seek(FIRST_IFD_OFFSET)
        fixture.write(struct.pack("<Q", 1))
        fixture.write(entry)
        fixture.write(struct.pack("<Q", 0))
        fixture.seek(EXTERNAL_VALUE_OFFSET)
        fixture.write(struct.pack("<QQ", 1, 1))
        fixture.truncate(FILE_SIZE)

    if os.path.getsize(path) != FILE_SIZE:
        raise RuntimeError("BigTIFF fixture size did not match its declared sparse layout")


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} OUTPUT")

    build_fixture(sys.argv[1])
    print(f"first_ifd_offset={FIRST_IFD_OFFSET}")
    print(f"external_value_offset={EXTERNAL_VALUE_OFFSET}")
    print(f"file_size={FILE_SIZE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
