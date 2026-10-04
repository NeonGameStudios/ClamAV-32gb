#!/usr/bin/env python3
"""Bounded, independent literal and checksum oracle for large raw fixtures.

Unlike line-oriented search tools, this reader never retains a whole input
line. A case is NAME:HEX:OFFSET, where OFFSET is a decimal byte offset or
"absent". A numeric offset requires exactly one occurrence at that offset.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


CHUNK_BYTES = 4 * 1024 * 1024
MAX_CASES = 16
MAX_NEEDLE_BYTES = 4096
NAME_RE = re.compile(r"[a-z][a-z0-9_-]*\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")


def parse_case(value: str) -> tuple[str, bytes, int | None]:
    parts = value.split(":", 2)
    if len(parts) != 3:
        raise ValueError("case must be NAME:HEX:OFFSET or NAME:HEX:absent")
    name, hex_literal, expected = parts
    if not NAME_RE.fullmatch(name):
        raise ValueError(f"invalid case name: {name!r}")
    if (not hex_literal or len(hex_literal) % 2
            or len(hex_literal) > 2 * MAX_NEEDLE_BYTES
            or not re.fullmatch(r"[0-9a-fA-F]+", hex_literal)):
        raise ValueError(f"invalid hex literal for {name}")
    needle = bytes.fromhex(hex_literal)
    if expected == "absent":
        offset = None
    elif expected.isascii() and expected.isdecimal():
        offset = int(expected)
    else:
        raise ValueError(f"invalid expected offset for {name}: {expected!r}")
    return name, needle, offset


def verify(
    path: Path,
    expected_size: int,
    expected_sha256: str,
    cases: list[tuple[str, bytes, int | None]],
    require_materialized: bool = False,
    chunk_bytes: int = CHUNK_BYTES,
) -> dict:
    if expected_size < 0 or not SHA_RE.fullmatch(expected_sha256):
        raise ValueError("expected size and lowercase SHA-256 are required")
    if not cases or len(cases) > MAX_CASES:
        raise ValueError(f"require 1 to {MAX_CASES} literal cases")
    if chunk_bytes < MAX_NEEDLE_BYTES:
        raise ValueError("chunk size is too small for bounded literals")
    names = [name for name, _, _ in cases]
    if len(set(names)) != len(names):
        raise ValueError("literal case names must be unique")
    if any(not needle or len(needle) > MAX_NEEDLE_BYTES for _, needle, _ in cases):
        raise ValueError("literal length is out of bounds")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        with os.fdopen(fd, "rb", buffering=0) as stream:
            fd = -1  # fdopen owns the descriptor from here on.
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
                raise ValueError("input is not a regular file of the expected size")
            allocated_bytes = before.st_blocks * 512
            first_hole: int | None = None
            if require_materialized:
                if allocated_bytes < before.st_size:
                    raise ValueError("input has fewer allocated bytes than its size")
                if not hasattr(os, "SEEK_HOLE"):
                    raise ValueError("SEEK_HOLE is unavailable for allocation proof")
                try:
                    first_hole = os.lseek(stream.fileno(), 0, os.SEEK_HOLE)
                except OSError as error:
                    raise ValueError(f"SEEK_HOLE failed: {error}") from error
                if first_hole < before.st_size:
                    raise ValueError(f"input has a hole at offset {first_hole}")
                os.lseek(stream.fileno(), 0, os.SEEK_SET)

            counts = {name: 0 for name in names}
            first_offsets: dict[str, int | None] = {name: None for name in names}
            max_overlap = max(len(needle) for _, needle, _ in cases) - 1
            tail = b""
            digest = hashlib.sha256()
            total = 0
            while True:
                block = stream.read(chunk_bytes)
                if not block:
                    break
                digest.update(block)
                for name, needle, expected_offset in cases:
                    overlap = len(needle) - 1
                    prefix = tail[-overlap:] if overlap else b""
                    window = prefix + block
                    cursor = 0
                    while True:
                        pos = window.find(needle, cursor)
                        if pos < 0:
                            break
                        offset = total - len(prefix) + pos
                        counts[name] += 1
                        if first_offsets[name] is None:
                            first_offsets[name] = offset
                        if (counts[name] > (0 if expected_offset is None else 1)
                                or (expected_offset is not None
                                    and first_offsets[name] != expected_offset)):
                            raise ValueError(f"{name} occurred at an unexpected offset")
                        cursor = pos + 1
                total += len(block)
                tail = (tail + block)[-max_overlap:] if max_overlap else b""

            after = os.fstat(stream.fileno())
            stable_fields = (
                "st_dev", "st_ino", "st_size", "st_mtime_ns",
                "st_ctime_ns", "st_blocks",
            )
            if any(getattr(before, field) != getattr(after, field)
                   for field in stable_fields):
                raise ValueError("input metadata changed during the oracle read")
            if total != expected_size or digest.hexdigest() != expected_sha256:
                raise ValueError("input length or SHA-256 differs from the oracle")
            for name, _, expected_offset in cases:
                expected_count = 0 if expected_offset is None else 1
                if counts[name] != expected_count or first_offsets[name] != expected_offset:
                    raise ValueError(
                        f"{name} count/offset mismatch: "
                        f"{counts[name]}/{first_offsets[name]}"
                    )

            return {
                "version": 1,
                "bytes_read": total,
                "sha256": digest.hexdigest(),
                "allocated_bytes": allocated_bytes,
                "materialized_check": require_materialized,
                "first_hole_offset": first_hole,
                "chunk_bytes": chunk_bytes,
                "stable_metadata": True,
                "cases": {
                    name: {
                        "needle_hex": needle.hex(),
                        "count": counts[name],
                        "first_offset": first_offsets[name],
                    }
                    for name, needle, _ in cases
                },
            }
    finally:
        if fd >= 0:
            os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--expected-size", type=int, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--case", action="append", required=True)
    parser.add_argument("--require-materialized", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = verify(
            args.file,
            args.expected_size,
            args.expected_sha256,
            [parse_case(value) for value in args.case],
            args.require_materialized,
        )
    except (OSError, ValueError) as error:
        print(f"binary literal oracle failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
