#!/usr/bin/env python3
"""Validate the sparse boundary corpus independently of the scanner.

The boundary generator's manifest is an oracle, not a declaration to trust.
This checker validates the complete row set, logical sizes, sparse allocation,
and marker bytes before any scanner is run.  It reads only the marker window,
so checking a 32-GiB sparse fixture does not traverse its holes.
"""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path
import stat
import sys


MANIFEST_HEADER = ("file", "marker", "offset", "size", "kind")


def _row(file_name: str, marker: str, offset: int, size: int) -> tuple[str, str, int, int, str]:
    return (file_name, marker, offset, size, "sparse-boundary")


ROWS = (
    _row("2g-minus.bin", "CLAMAV-LF-2g-minus", 2_147_483_647, 2_147_483_711),
    _row("2g.bin", "CLAMAV-LF-2g", 2_147_483_648, 2_147_483_712),
    _row("2g-plus.bin", "CLAMAV-LF-2g-plus", 2_147_483_649, 2_147_483_713),
    _row("4g-minus-two.bin", "CLAMAV-LF-4g-minus-two", 4_294_967_294, 4_294_967_358),
    _row("4g-minus.bin", "CLAMAV-LF-4g-minus", 4_294_967_295, 4_294_967_359),
    _row("4g.bin", "CLAMAV-LF-4g", 4_294_967_296, 4_294_967_360),
    _row("4g-plus.bin", "CLAMAV-LF-4g-plus", 4_294_967_297, 4_294_967_361),
    _row("8g.bin", "CLAMAV-LF-8g", 8_589_934_592, 8_589_934_656),
    _row("16g.bin", "CLAMAV-LF-16g", 17_179_869_184, 17_179_869_248),
    _row("32g-head.bin", "CLAMAV-LF-32G-HEAD", 4_096, 34_359_738_368),
    _row("32g-edge.bin", "CLAMAV-LF-32G-EDGE", 34_359_738_304, 34_359_738_368),
)


def fail(message: str) -> None:
    raise ValueError(message)


def manifest_rows(path: Path) -> list[tuple[str, str, int, int, str]]:
    if not path.is_file() or path.is_symlink():
        fail(f"boundary manifest is missing or symlinked: {path}")
    try:
        with path.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.reader(stream, delimiter="\t", strict=True))
    except csv.Error as error:
        fail(f"boundary manifest has malformed TSV: {error}")
    if not rows or tuple(rows[0]) != MANIFEST_HEADER:
        fail("boundary manifest has an invalid header")
    parsed = []
    for line_number, fields in enumerate(rows[1:], start=2):
        if len(fields) != len(MANIFEST_HEADER):
            fail(f"boundary manifest has an invalid row at line {line_number}")
        file_name, marker, offset_text, size_text, kind = fields
        if not file_name or file_name.startswith("/") or "/" in file_name or file_name in {".", ".."}:
            fail(f"boundary manifest has an unsafe file name at line {line_number}")
        if not marker or not offset_text.isdigit() or not size_text.isdigit():
            fail(f"boundary manifest has invalid numeric fields at line {line_number}")
        parsed.append((file_name, marker, int(offset_text), int(size_text), kind))
    return parsed


def file_identity(info: os.stat_result) -> tuple:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        getattr(info, "st_blocks", None),
    )


def validate_file(corpus: Path, row: tuple[str, str, int, int, str]) -> dict[str, int | str]:
    file_name, marker, offset, size, kind = row
    if kind != "sparse-boundary":
        fail(f"{file_name} has an unexpected corpus kind: {kind}")
    if size < offset + 64:
        fail(f"{file_name} does not contain the specified 64-byte marker window")
    path = corpus / file_name
    if path.is_symlink() or not path.is_file():
        fail(f"boundary fixture is missing or not a regular file: {file_name}")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail(f"boundary fixture is not a regular file: {file_name}")
        if before.st_size != size:
            fail(f"{file_name} has size {before.st_size}, expected {size}")
        blocks = getattr(before, "st_blocks", None)
        if type(blocks) is not int or blocks < 0:
            fail(f"{file_name} has no usable sparse-allocation metadata")
        allocated = blocks * 512
        if allocated >= size:
            fail(f"{file_name} is not sparse: {allocated} allocated bytes for {size} bytes")
        expected = marker.encode("utf-8") + b"\0" * (64 - len(marker.encode("utf-8")))
        if len(expected) != 64:
            fail(f"{file_name} marker does not fit the 64-byte window")
        actual = os.pread(descriptor, 64, offset)
        if actual != expected:
            fail(f"{file_name} marker window does not match its independent oracle")
        after = os.fstat(descriptor)
        if file_identity(before) != file_identity(after) or file_identity(before) != file_identity(path.stat()):
            fail(f"{file_name} changed while its boundary oracle was checked")
    finally:
        os.close(descriptor)
    return {"size": size, "allocated_bytes": allocated, "offset": offset}


def validate_corpus(corpus: Path) -> list[dict[str, int | str]]:
    corpus = corpus.resolve()
    if not corpus.is_dir() or corpus.is_symlink():
        fail(f"boundary corpus is not a directory: {corpus}")
    actual = manifest_rows(corpus / "manifest.tsv")
    if actual != list(ROWS):
        fail("boundary manifest rows do not match the reviewed boundary oracle")
    return [validate_file(corpus, row) for row in actual]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    args = parser.parse_args(argv)
    results = validate_corpus(args.corpus)
    print(f"boundary_corpus=pass rows={len(results)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, UnicodeError) as error:
        print(f"large-file boundary corpus verification failed: {error}", file=sys.stderr)
        sys.exit(1)
