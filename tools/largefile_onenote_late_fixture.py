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
import os
import stat
import struct
from pathlib import Path


FORMER_WHOLE_INPUT_CAP = 256 * 1024 * 1024
CELL_SCHEMA = bytes.fromhex("b47c931f6fb25f44b9f817e20160e461")
DATA_ELEMENT_TYPE = 0x01
OBJECT_DATA_BLOB_TYPE = 0x02
DATA_ELEMENT_END = bytes(((DATA_ELEMENT_TYPE << 2) | 0x01,))


def write_all(output, data: bytes) -> None:
    """Write a complete buffer, even when the underlying stream short-writes."""
    view = memoryview(data)
    while view:
        written = output.write(view)
        if written is None or written <= 0:
            raise OSError("fixture output stopped accepting bytes")
        view = view[written:]


def remove_partial_output(path: Path, identity: tuple[int, int] | None) -> None:
    """Remove a failed output only when its current inode is still ours."""
    if identity is None:
        raise OSError("cannot verify ownership of the partial fixture")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (metadata.st_dev, metadata.st_ino) != identity:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


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


def payload_size_for_target(source_path: Path, target_bytes: int) -> int:
    """Compute the inserted payload needed for an exact final file size."""
    fixed_size = (
        source_path.stat().st_size
        + len(build_prefix(0))
        + len(DATA_ELEMENT_END)
    )
    payload_size = target_bytes - fixed_size
    if payload_size < FORMER_WHOLE_INPUT_CAP:
        raise ValueError(
            "target file size cannot include the required payload beyond the "
            "former 256 MiB whole-input cap"
        )
    # Validate that the computed payload fits the encoded compact-u64 field.
    build_prefix(payload_size)
    return payload_size


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
    late_marker_offset = marker_offset + len(prefix) + payload_size + len(DATA_ELEMENT_END)
    if late_marker_offset <= FORMER_WHOLE_INPUT_CAP:
        raise AssertionError("fixture did not move the embedded marker beyond the cap")

    chunk = b"\x00" * (1024 * 1024)
    output_identity = None
    output_created = False
    expected_size = len(source) + len(prefix) + payload_size + len(DATA_ELEMENT_END)
    try:
        with output_path.open("xb") as output:
            output_created = True
            metadata = os.fstat(output.fileno())
            output_identity = (metadata.st_dev, metadata.st_ino)
            write_all(output, source[:first_element])
            write_all(output, prefix)
            remaining = payload_size
            while remaining:
                count = min(remaining, len(chunk))
                write_all(output, chunk[:count])
                remaining -= count
            write_all(output, DATA_ELEMENT_END)
            write_all(output, source[first_element:])

        metadata = output_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or output_identity != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            raise OSError("fixture output path changed during generation")
        if metadata.st_size != expected_size:
            raise OSError("materialized fixture has an unexpected final size")
    except BaseException as generation_error:
        # Remove only the partial inode created by this invocation. If another
        # process replaced the pathname, preserve that unrelated file.
        if output_created:
            try:
                remove_partial_output(output_path, output_identity)
            except OSError as cleanup_error:
                raise OSError(
                    "fixture generation failed and partial output may remain at "
                    f"{output_path}: {cleanup_error}"
                ) from generation_error
        raise

    return late_marker_offset


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="valid decrypted modern .one file")
    parser.add_argument("output", type=Path, help="new materialized late-child .one file")
    size = parser.add_mutually_exclusive_group()
    size.add_argument(
        "--payload-bytes",
        type=int,
        default=None,
        help="zero-byte ObjectDataBlob inserted before the original data elements",
    )
    size.add_argument(
        "--target-bytes",
        type=int,
        help="exact final materialized file size; computes the inserted payload length",
    )
    args = parser.parse_args()
    if args.target_bytes is not None:
        payload_size = payload_size_for_target(args.source, args.target_bytes)
    elif args.payload_bytes is not None:
        payload_size = args.payload_bytes
    else:
        payload_size = FORMER_WHOLE_INPUT_CAP
    marker = write_fixture(args.source, args.output, payload_size)
    print(
        f"created={args.output} size={args.output.stat().st_size} "
        f"embedded_mz_offset={marker} payload_bytes={payload_size}"
    )


if __name__ == "__main__":
    main()
