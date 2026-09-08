#!/usr/bin/env python3
"""Build and independently oracle a deterministic ZIP late-member fixture."""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile


PREFIX_MEMBER = "prefix.bin"
TARGET_MEMBER = "late-marker.bin"
MARKER = b"CLAMAV-ZIP-LATE-MEMBER-MARKER"
PREFIX_SIZE = (128 * 1024) + 17
TARGET_PREFIX_SIZE = 32 * 1024 + 11
EOCD = struct.Struct("<4s4H2IH")
CENTRAL = struct.Struct("<4s6H3I5H2I")
LOCAL = struct.Struct("<4s5H3I2H")


def fail(message: str) -> None:
    raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    prefix = b"P" * PREFIX_SIZE
    target = b"T" * TARGET_PREFIX_SIZE + MARKER + b"\n"
    prefix_info = zipfile.ZipInfo(PREFIX_MEMBER, (1980, 1, 1, 0, 0, 0))
    target_info = zipfile.ZipInfo(TARGET_MEMBER, (1980, 1, 1, 0, 0, 0))
    for info in (prefix_info, target_info):
        # Do not inherit host-specific creator/version or permission metadata.
        # The raw oracle intentionally checks the bytes emitted by this
        # generator, so the generator must make those bytes deterministic too.
        info.create_system = 3  # Unix
        info.external_attr = 0o600 << 16
        info.compress_type = zipfile.ZIP_STORED
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        archive.writestr(prefix_info, prefix)
        archive.writestr(target_info, target)


def _find_eocd(data: bytes) -> tuple[int, tuple]:
    offset = data.rfind(b"PK\x05\x06")
    if offset < 0:
        fail("ZIP end-of-central-directory record is missing")
    if offset + EOCD.size > len(data):
        fail("ZIP end-of-central-directory record is truncated")
    record = EOCD.unpack_from(data, offset)
    if record[1] != 0 or record[2] != 0 or record[3] != record[4]:
        fail("multi-disk or inconsistent ZIP directory is unsupported")
    comment_length = record[7]
    if offset + EOCD.size + comment_length != len(data):
        fail("ZIP comment length does not reach EOF")
    # EOCD fields are: signature, disk, directory disk, entries-on-disk,
    # entries, directory size, directory offset, comment length.
    directory_size = record[5]
    directory_offset = record[6]
    if directory_offset + directory_size != offset:
        fail("ZIP central-directory bounds are inconsistent")
    return offset, record


def build_oracle(path: Path) -> dict:
    data = path.read_bytes()
    _, eocd = _find_eocd(data)
    total_entries = eocd[4]
    directory_size = eocd[5]
    directory_offset = eocd[6]
    cursor = directory_offset
    target = None
    names = []
    for _ in range(total_entries):
        if cursor + CENTRAL.size > len(data):
            fail("ZIP central-directory entry is truncated")
        values = CENTRAL.unpack_from(data, cursor)
        if values[0] != b"PK\x01\x02":
            fail("ZIP central-directory signature is invalid")
        (_, _, _, flags, method, _, _, crc, compressed_size, uncompressed_size,
         name_length, extra_length, comment_length, disk_start, _, _, local_offset) = values
        if flags & ~0x800 or method != zipfile.ZIP_STORED or disk_start != 0:
            fail("ZIP fixture uses unsupported flags, compression, or disks")
        end = cursor + CENTRAL.size + name_length + extra_length + comment_length
        if end > directory_offset + directory_size:
            fail("ZIP central-directory entry exceeds its declared range")
        name_bytes = data[cursor + CENTRAL.size:cursor + CENTRAL.size + name_length]
        name = name_bytes.decode("utf-8" if flags & 0x800 else "cp437")
        names.append(name)
        if name == TARGET_MEMBER:
            if target is not None:
                fail("ZIP target member is duplicated")
            target = {
                "flags": flags,
                "method": method,
                "crc": crc,
                "compressed_size": compressed_size,
                "uncompressed_size": uncompressed_size,
                "name_length": name_length,
                "extra_length": extra_length,
                "local_offset": local_offset,
            }
        cursor = end
    if cursor != directory_offset + directory_size:
        fail("ZIP central-directory size does not match its entries")
    if not names:
        fail("ZIP central-directory has no entries")
    if target is None or names[-1] != TARGET_MEMBER:
        fail("ZIP target member is not the final late member")
    local_offset = target["local_offset"]
    if local_offset + LOCAL.size > directory_offset:
        fail("ZIP target local header is outside the file-data range")
    local = LOCAL.unpack_from(data, local_offset)
    if local[0] != b"PK\x03\x04":
        fail("ZIP target local-header signature is invalid")
    _, _, local_flags, local_method, _, _, local_crc, local_compressed, local_uncompressed, local_name_length, local_extra_length = local
    for actual, expected in (
        (local_flags, target["flags"]),
        (local_method, target["method"]),
        (local_crc, target["crc"]),
        (local_compressed, target["compressed_size"]),
        (local_uncompressed, target["uncompressed_size"]),
        (local_name_length, target["name_length"]),
        (local_extra_length, target["extra_length"]),
    ):
        if actual != expected:
            fail("ZIP local and central target metadata disagree")
    name_start = local_offset + LOCAL.size
    data_start = name_start + local_name_length + local_extra_length
    data_end = data_start + target["compressed_size"]
    if data_end > directory_offset or data_end > len(data):
        fail("ZIP target member data exceeds its declared range")
    payload = data[data_start:data_end]
    if binascii.crc32(payload) & 0xFFFFFFFF != target["crc"]:
        fail("ZIP target member CRC does not match its central directory")
    marker_offsets = []
    cursor = payload.find(MARKER)
    while cursor >= 0:
        marker_offsets.append(cursor)
        cursor = payload.find(MARKER, cursor + 1)
    if len(marker_offsets) != 1:
        fail("ZIP target member does not contain exactly one marker")
    marker_offset = marker_offsets[0]
    return {
        "version": 1,
        "fixture_sha256": sha256(path),
        "fixture_size": len(data),
        "target_member": TARGET_MEMBER,
        "target_member_data_offset": data_start,
        "target_member_size": len(payload),
        "marker": MARKER.decode("ascii"),
        "marker_member_offset": marker_offset,
        "marker_file_offset": data_start + marker_offset,
        "marker_sha256": hashlib.sha256(MARKER).hexdigest(),
    }


def validate_oracle(path: Path, oracle: dict) -> dict:
    expected = build_oracle(path)
    if oracle != expected:
        fail("ZIP oracle does not match the independently parsed fixture")
    return expected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--oracle", type=Path)
    args = parser.parse_args(argv)
    try:
        build_fixture(args.fixture)
        oracle = build_oracle(args.fixture)
        if args.oracle:
            args.oracle.write_text(json.dumps(oracle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(oracle, sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"large-file ZIP fixture failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    import sys
    raise SystemExit(main())
