#!/usr/bin/env python3
"""Build a reproducible materialized OneNote late-child fixture.

The source is an existing valid modern OneNote section.  An unreferenced
FSSHTTPB ObjectDataBlob is inserted at the start of its data-element package;
the original data elements and identifiers remain byte-for-byte unchanged.
The blob is deliberately written as real zero bytes, not a sparse hole, so a
consumer can distinguish a physically materialized oversized file from a
logical-length reader test.
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


FORMER_WHOLE_INPUT_CAP = 256 * 1024 * 1024
CELL_SCHEMA = bytes.fromhex("b47c931f6fb25f44b9f817e20160e461")
DATA_ELEMENT_TYPE = 0x01
OBJECT_DATA_BLOB_TYPE = 0x02
DATA_ELEMENT_END = bytes(((DATA_ELEMENT_TYPE << 2) | 0x01,))


def object_header_16(object_type: int, *, compound: bool = True) -> bytes:
    value = (object_type << 3) | (0x04 if compound else 0)
    return struct.pack("<H", value)


def compact_u64(value: int) -> bytes:
    if value < 0 or value >= 1 << 64:
        raise ValueError("compact-u64 value is outside the u64 range")
    return b"\x80" + struct.pack("<Q", value)


def find_package_start(source: bytes) -> int:
    schema_offset = source.find(CELL_SCHEMA)
    if schema_offset < 0:
        raise ValueError("modern section cell-schema GUID was not found")
    package_start = schema_offset + len(CELL_SCHEMA)
    if package_start + 3 > len(source):
        raise ValueError("section ends before its data-element package")

    package_header = struct.unpack_from("<H", source, package_start)[0]
    package_type = (package_header >> 3) & 0x3F
    if package_type != 0x15:
        raise ValueError("cell schema is not followed by a data-element package")
    if source[package_start + 2] != 0:
        raise ValueError("data-element package has nonzero padding")
    return package_start


def build_prefix(payload_size: int) -> bytes:
    # DataElement: null ExGuid, null SerialNumber, element type 0x0A.
    # ObjectDataBlob: compact payload size, payload, and DataElement end.
    return (
        object_header_16(DATA_ELEMENT_TYPE)
        + b"\x00"  # null data-element ExGuid
        + b"\x00"  # null serial number
        + bytes(((0x0A << 1) | 0x01,))
        + object_header_16(OBJECT_DATA_BLOB_TYPE)
        + compact_u64(payload_size)
    )


def write_fixture(source_path: Path, output_path: Path, payload_size: int) -> int:
    if output_path.exists():
        raise FileExistsError(f"refusing to overwrite existing output: {output_path}")
    if payload_size < FORMER_WHOLE_INPUT_CAP:
        raise ValueError("payload must reach the former 256 MiB whole-input cap")

    source = source_path.read_bytes()
    package_start = find_package_start(source)
    first_element = package_start + 3
    first_header = struct.unpack_from("<H", source, first_element)[0]
    if ((first_header >> 3) & 0x3F) != DATA_ELEMENT_TYPE:
        raise ValueError("data-element package does not begin with a data element")

    prefix = build_prefix(payload_size)
    marker_offset = source.find(b"MZ")
    if marker_offset < 0:
        raise ValueError("source fixture has no embedded MZ marker")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    chunk = b"\x00" * (1024 * 1024)
    with output_path.open("xb") as output:
        output.write(source[:first_element])
        output.write(prefix)
        remaining = payload_size
        while remaining:
            count = min(remaining, len(chunk))
            output.write(chunk[:count])
            remaining -= count
        output.write(DATA_ELEMENT_END)
        output.write(source[first_element:])

    late_marker_offset = marker_offset + len(prefix) + payload_size + len(DATA_ELEMENT_END)
    if late_marker_offset <= FORMER_WHOLE_INPUT_CAP:
        raise AssertionError("fixture did not move the embedded marker beyond the cap")
    return late_marker_offset


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="valid decrypted modern .one file")
    parser.add_argument("output", type=Path, help="new materialized late-child .one file")
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=FORMER_WHOLE_INPUT_CAP,
        help="zero-byte ObjectDataBlob inserted before the original data elements",
    )
    args = parser.parse_args()
    marker = write_fixture(args.source, args.output, args.payload_bytes)
    print(
        f"created={args.output} size={args.output.stat().st_size} "
        f"embedded_mz_offset={marker} payload_bytes={args.payload_bytes}"
    )


if __name__ == "__main__":
    main()
