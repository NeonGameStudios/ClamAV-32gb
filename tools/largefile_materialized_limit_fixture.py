#!/usr/bin/env python3
"""Write the 32-GiB-plus-one direct-file limit fixture to disk, never sparse.

This is an input generator, not a scan or qualification result. The CLI has
no size override: small sizes are available only to its unit tests. It checks
that the target filesystem has enough free space for the fixture plus the
release temporary-space admission minimum before writing any file.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile


GIB = 1024 ** 3
LIMIT_SIZE = 32 * GIB + 1
MIN_FREE_AFTER = 68 * GIB
SAFETY_HEADROOM = GIB
CHUNK_SIZE = 4 * 1024 * 1024
PATTERN = bytes(range(256)) * (CHUNK_SIZE // 256)
TAIL = b"CLAMAV-LIMIT-PLUS1"
# Independent of the generated file: SHA-256 of 8,191 complete 4-MiB pattern
# chunks, then the first 4 MiB - (len(TAIL) - 1) bytes of the final pattern
# chunk and TAIL. The result covers exactly 32 GiB + 1 byte.
LIMIT_EXPECTED_SHA256 = "e5ac6089ac04599810af19a2d93858c841e307037fa016f90efad197ec606720"
STABLE_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_blocks")


def fail(message: str) -> None:
    raise ValueError(message)


def materialize(destination: Path, size: int = LIMIT_SIZE,
                min_free_after: int = MIN_FREE_AFTER,
                safety_headroom: int = SAFETY_HEADROOM) -> dict[str, int | str]:
    if not destination.is_absolute() or ".." in destination.parts or \
            not destination.parent.is_dir() or destination.parent.is_symlink() or \
            destination.exists() or destination.is_symlink():
        fail("limit fixture destination must be a new absolute file in an existing directory")
    if size < len(TAIL) or min_free_after < 0 or safety_headroom < 0:
        fail("limit fixture size or admission headroom is invalid")
    filesystem = os.statvfs(destination.parent)
    free_bytes = filesystem.f_bavail * filesystem.f_frsize
    required = size + min_free_after + safety_headroom
    if free_bytes < required:
        fail(f"limit fixture needs {required} free bytes before writing; only {free_bytes} available")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.partial-", dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        written = 0
        while written < size:
            chunk = PATTERN[:min(CHUNK_SIZE, size - written)]
            view = memoryview(chunk)
            while view:
                count = os.write(descriptor, view)
                if count < 1:
                    fail("limit fixture write made no progress")
                view = view[count:]
                written += count
        if os.pwrite(descriptor, TAIL, size - len(TAIL)) != len(TAIL):
            fail("limit fixture tail marker was not written completely")
        os.fsync(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != size or \
                before.st_blocks * 512 < size:
            fail("limit fixture size or physical allocation is incomplete")
        try:
            first_hole = os.lseek(descriptor, 0, os.SEEK_HOLE)
        except OSError as error:
            raise ValueError("limit fixture hole layout cannot be verified") from error
        if first_hole != size:
            fail(f"limit fixture has a hole before EOF at byte {first_hole}")
        if os.pread(descriptor, len(TAIL), size - len(TAIL)) != TAIL or \
                os.pread(descriptor, 256, 0) != PATTERN[:256]:
            fail("limit fixture bytes do not match the reviewed pattern/tail")
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, CHUNK_SIZE):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if any(getattr(before, field) != getattr(after, field) for field in STABLE_FIELDS):
            fail("limit fixture changed during its full-content hash")
        actual_sha256 = digest.hexdigest()
        if size == LIMIT_SIZE and actual_sha256 != LIMIT_EXPECTED_SHA256:
            fail("limit fixture differs from the independently pinned 32-GiB-plus-one digest")
        os.link(temporary, destination)
        temporary.unlink()
        return {
            "size": size, "sha256": actual_sha256,
            "allocated_bytes": after.st_blocks * 512,
            "first_hole": first_hole, "tail_hex": TAIL.hex(),
        }
    finally:
        os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def interrupted(signum: int, _frame: object) -> None:
    raise InterruptedError(f"limit fixture generation interrupted by signal {signum}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--acknowledge-full-write", action="store_true",
                        help="explicitly authorize writing and rehashing 32 GiB + 1 byte")
    args = parser.parse_args(argv)
    if not args.acknowledge_full_write:
        parser.error("the fixed 32-GiB-plus-one write requires --acknowledge-full-write")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        result = materialize(args.destination)
    except (OSError, ValueError, InterruptedError) as error:
        print(f"materialized limit fixture failed: {error}", file=sys.stderr)
        return 1
    print(f"materialized limit fixture: {args.destination}")
    for key, value in result.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
