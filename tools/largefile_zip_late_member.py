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
WRITE_CHUNK_SIZE = 1024 * 1024
EOCD = struct.Struct("<4s4H2IH")
CENTRAL = struct.Struct("<4s6H3I5H2I")
LOCAL = struct.Struct("<4s5H3I2H")
ZIP64_LOCATOR = struct.Struct("<4sIQI")
ZIP64_EOCD = struct.Struct("<4sQ2H2I4Q")
UINT16_MAX = (1 << 16) - 1
UINT32_MAX = (1 << 32) - 1


def fail(message: str) -> None:
    raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_repeated(stream, value: int, count: int) -> None:
    if count < 0:
        fail("fixture member size cannot be negative")
    block = bytes([value]) * min(WRITE_CHUNK_SIZE, count)
    while count:
        written = min(count, len(block))
        stream.write(block[:written])
        count -= written


def build_fixture(
    path: Path,
    prefix_size: int = PREFIX_SIZE,
    target_prefix_size: int = TARGET_PREFIX_SIZE,
) -> None:
    """Build a stored late-member fixture without buffering its payloads.

    The size arguments are intentionally configurable so a certified runner
    can place the target marker at a multi-gigabyte outer-file coordinate.
    ``zipfile`` is still used only for writing the container; the oracle below
    parses the resulting bytes independently.
    """
    if prefix_size < 0 or target_prefix_size < 0:
        fail("fixture member sizes cannot be negative")
    path.parent.mkdir(parents=True, exist_ok=True)
    prefix_info = zipfile.ZipInfo(PREFIX_MEMBER, (1980, 1, 1, 0, 0, 0))
    target_info = zipfile.ZipInfo(TARGET_MEMBER, (1980, 1, 1, 0, 0, 0))
    for info in (prefix_info, target_info):
        # Do not inherit host-specific creator/version or permission metadata.
        # The raw oracle intentionally checks the bytes emitted by this
        # generator, so the generator must make those bytes deterministic too.
        info.create_system = 3  # Unix
        info.external_attr = 0o600 << 16
        info.compress_type = zipfile.ZIP_STORED
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        with archive.open(prefix_info, "w", force_zip64=prefix_size >= UINT32_MAX) as prefix:
            _write_repeated(prefix, ord("P"), prefix_size)
        target_size = target_prefix_size + len(MARKER) + 1
        with archive.open(target_info, "w", force_zip64=target_size >= UINT32_MAX) as target:
            _write_repeated(target, ord("T"), target_prefix_size)
            target.write(MARKER)
            target.write(b"\n")


def _read_at(stream, offset: int, count: int) -> bytes:
    if offset < 0 or count < 0:
        fail("ZIP read range is negative")
    stream.seek(offset)
    data = stream.read(count)
    if len(data) != count:
        fail("ZIP range is truncated")
    return data


def _zip64_extra_values(extra: bytes, needed: tuple[bool, ...]) -> list[int]:
    if not any(needed):
        return []
    cursor = 0
    while cursor + 4 <= len(extra):
        field_id, field_size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        end = cursor + field_size
        if end > len(extra):
            fail("ZIP extra field is truncated")
        if field_id == 0x0001:
            payload = extra[cursor:end]
            values = []
            payload_cursor = 0
            for required in needed:
                if required:
                    if payload_cursor + 8 > len(payload):
                        fail("ZIP64 extra field is truncated")
                    values.append(struct.unpack_from("<Q", payload, payload_cursor)[0])
                    payload_cursor += 8
            return values
        cursor = end
    fail("ZIP64 extra field is missing")


def _find_eocd(stream, file_size: int) -> tuple[int, int, int, int]:
    tail_size = min(file_size, EOCD.size + 0xFFFF)
    tail_offset = file_size - tail_size
    tail = _read_at(stream, tail_offset, tail_size)
    relative_offset = tail.rfind(b"PK\x05\x06")
    if relative_offset < 0:
        fail("ZIP end-of-central-directory record is missing")
    offset = tail_offset + relative_offset
    if offset + EOCD.size > file_size:
        fail("ZIP end-of-central-directory record is truncated")
    record = EOCD.unpack(_read_at(stream, offset, EOCD.size))
    if record[1] != 0 or record[2] != 0 or record[3] != record[4]:
        fail("multi-disk or inconsistent ZIP directory is unsupported")
    comment_length = record[7]
    if offset + EOCD.size + comment_length != file_size:
        fail("ZIP comment length does not reach EOF")
    # EOCD fields are: signature, disk, directory disk, entries-on-disk,
    # entries, directory size, directory offset, comment length.
    total_entries = record[4]
    directory_size = record[5]
    directory_offset = record[6]
    if (directory_size == UINT32_MAX or directory_offset == UINT32_MAX or
            total_entries == UINT16_MAX):
        locator_offset = offset - ZIP64_LOCATOR.size
        if locator_offset < 0:
            fail("ZIP64 locator is missing")
        locator = ZIP64_LOCATOR.unpack(_read_at(stream, locator_offset, ZIP64_LOCATOR.size))
        if locator[0] != b"PK\x06\x07" or locator[1] != 0 or locator[3] != 1:
            fail("ZIP64 locator is invalid")
        zip64_offset = locator[2]
        header = _read_at(stream, zip64_offset, ZIP64_EOCD.size)
        values = ZIP64_EOCD.unpack(header)
        if values[0] != b"PK\x06\x06" or values[1] < 44:
            fail("ZIP64 end-of-central-directory record is invalid")
        if values[4] != 0 or values[5] != 0 or values[6] != values[7]:
            fail("multi-disk ZIP64 directory is unsupported")
        total_entries = values[7]
        directory_size = values[8]
        directory_offset = values[9]
        directory_end = zip64_offset
    else:
        directory_end = offset
    if directory_offset + directory_size != directory_end:
        fail("ZIP central-directory bounds are inconsistent")
    return offset, total_entries, directory_size, directory_offset


def build_oracle(path: Path) -> dict:
    file_size = path.stat().st_size
    with path.open("rb") as stream:
        _, total_entries, directory_size, directory_offset = _find_eocd(stream, file_size)
        cursor = directory_offset
        target = None
        names = []
        for _ in range(total_entries):
            if cursor + CENTRAL.size > directory_offset + directory_size:
                fail("ZIP central-directory entry is truncated")
            values = CENTRAL.unpack(_read_at(stream, cursor, CENTRAL.size))
            if values[0] != b"PK\x01\x02":
                fail("ZIP central-directory signature is invalid")
            (_, _, _, flags, method, _, _, crc, compressed_size, uncompressed_size,
             name_length, extra_length, comment_length, disk_start, _, _, local_offset) = values
            extra_start = cursor + CENTRAL.size + name_length
            extra = _read_at(stream, extra_start, extra_length)
            if flags & ~0x800 or method != zipfile.ZIP_STORED or disk_start != 0:
                fail("ZIP fixture uses unsupported flags, compression, or disks")
            end = cursor + CENTRAL.size + name_length + extra_length + comment_length
            if end > directory_offset + directory_size:
                fail("ZIP central-directory entry exceeds its declared range")
            name_bytes = _read_at(stream, cursor + CENTRAL.size, name_length)
            name = name_bytes.decode("utf-8" if flags & 0x800 else "cp437")
            names.append(name)
            resolved_uncompressed, resolved_compressed, resolved_offset = _zip64_extra_values(
                extra,
                (uncompressed_size == UINT32_MAX, compressed_size == UINT32_MAX,
                 local_offset == UINT32_MAX),
            ) or (None, None, None)
            if uncompressed_size == UINT32_MAX:
                uncompressed_size = resolved_uncompressed
            if compressed_size == UINT32_MAX:
                compressed_size = resolved_compressed
            if local_offset == UINT32_MAX:
                local_offset = resolved_offset
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
        local = LOCAL.unpack(_read_at(stream, local_offset, LOCAL.size))
        if local[0] != b"PK\x03\x04":
            fail("ZIP target local-header signature is invalid")
        _, _, local_flags, local_method, _, _, local_crc, local_compressed, local_uncompressed, local_name_length, local_extra_length = local
        local_extra = _read_at(stream, local_offset + LOCAL.size + local_name_length, local_extra_length)
        local_uncompressed_value, local_compressed_value = _zip64_extra_values(
            local_extra,
            (local_uncompressed == UINT32_MAX, local_compressed == UINT32_MAX),
        ) or (None, None)
        if local_uncompressed == UINT32_MAX:
            local_uncompressed = local_uncompressed_value
        if local_compressed == UINT32_MAX:
            local_compressed = local_compressed_value
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
        if data_end > directory_offset or data_end > file_size:
            fail("ZIP target member data exceeds its declared range")

        crc_value = 0
        marker_offsets = []
        carry = b""
        payload_offset = 0
        while payload_offset < target["compressed_size"]:
            length = min(WRITE_CHUNK_SIZE, target["compressed_size"] - payload_offset)
            chunk = _read_at(stream, data_start + payload_offset, length)
            crc_value = binascii.crc32(chunk, crc_value) & 0xFFFFFFFF
            for index in range(len(chunk) - len(MARKER) + 1):
                if chunk[index:index + len(MARKER)] == MARKER:
                    marker_offsets.append(payload_offset + index)
            combined = carry + chunk
            for index in range(len(carry)):
                if combined[index:index + len(MARKER)] == MARKER:
                    marker_offsets.append(payload_offset - len(carry) + index)
            carry = combined[-(len(MARKER) - 1):]
            payload_offset += length
        if crc_value != target["crc"]:
            fail("ZIP target member CRC does not match its central directory")
        if len(marker_offsets) != 1:
            fail("ZIP target member does not contain exactly one marker")
        marker_offset = marker_offsets[0]
    return {
        "version": 1,
        "fixture_sha256": sha256(path),
        "fixture_size": file_size,
        "target_member": TARGET_MEMBER,
        "target_member_data_offset": data_start,
        "target_member_size": target["uncompressed_size"],
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
    parser.add_argument("--prefix-size", type=int, default=PREFIX_SIZE)
    parser.add_argument("--target-prefix-size", type=int, default=TARGET_PREFIX_SIZE)
    args = parser.parse_args(argv)
    try:
        build_fixture(args.fixture, args.prefix_size, args.target_prefix_size)
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
