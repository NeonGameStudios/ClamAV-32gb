#!/usr/bin/env python3
"""Assemble small retained case artifacts under one R04 evidence root.

The external full-size input is never copied. Each source root must already
contain one acceptance row; the staged bundle is independently validated
before publishing into a newly created output directory. This does not create a release
proof or qualify a capability with missing cases.
"""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import largefile_acceptance_cases as cases
import largefile_acceptance_resources as resources


MAX_ARTIFACT_BYTES = 128 * 1024 * 1024


def fail(message: str) -> None:
    raise ValueError(message)


def copy_artifact(source_root: Path, destination_root: Path, name: str,
                  max_bytes: int) -> None:
    relative = Path(name)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        fail(f"case bundle has an unsafe artifact path: {name}")
    source = cases.safe_evidence_file(source_root, name, "case bundle source artifact")
    target = destination_root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(source, flags), "rb") as input_stream:
        before = os.fstat(input_stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            fail(f"case bundle artifact exceeds the copy limit: {name}")
        with target.open("xb") as output_stream:
            while chunk := input_stream.read(1024 * 1024):
                output_stream.write(chunk)
        after = os.fstat(input_stream.fileno())
    current = os.stat(source, follow_symlinks=False)
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_blocks")
    if any(getattr(before, field) != getattr(after, field) or
           getattr(before, field) != getattr(current, field) for field in fields):
        fail(f"case bundle source artifact changed during copying: {name}")
    if cases.sha256(target) != cases.sha256(source):
        fail(f"case bundle artifact copy checksum differs: {name}")


def assemble(output: Path, source_roots: list[Path], mapping: list[dict[str, str]],
             max_artifact_bytes: int = MAX_ARTIFACT_BYTES) -> Path:
    if not source_roots or max_artifact_bytes < 1:
        fail("case bundle needs source roots and a positive artifact ceiling")
    output = output.absolute()
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        fail("case bundle output already exists or its parent is missing")
    rows: list[dict[str, str]] = []
    inputs: list[tuple[Path, dict[str, str]]] = []
    keys: set[tuple[str, str, str]] = set()
    for raw in source_roots:
        source = raw.resolve()
        if raw.is_symlink() or not source.is_dir():
            fail(f"case bundle source root is missing or symlinked: {raw}")
        record_path = cases.safe_evidence_file(
            source, "provenance/acceptance-cases.tsv", "case bundle private record",
        )
        private_rows = cases.read_tsv(record_path, cases.RECORD_HEADER)
        if len(private_rows) != 1:
            fail(f"case bundle source must contain one private case: {source}")
        row = private_rows[0]
        key = (row["kind"], row["id"], row["case_id"])
        if key in keys:
            fail(f"case bundle duplicates a case: {':'.join(key)}")
        keys.add(key)
        rows.append(row)
        inputs.append((source, row))
    if len({row["source_manifest_sha256"] for row in rows}) != 1:
        fail("case bundle mixes source manifests")

    staging = Path(tempfile.mkdtemp(prefix=".largefile-case-bundle-", dir=output.parent))
    try:
        (staging / "provenance").mkdir()
        roots: list[tuple[str, str, str, str]] = []
        for index, (source, row) in enumerate(inputs, start=1):
            relative_root = f"cases/{index:04d}"
            destination = staging / relative_root
            destination.mkdir(parents=True)
            artifacts = row["artifacts"].split(",")
            if len(artifacts) != len(set(artifacts)) or any(not name for name in artifacts):
                fail(f"case bundle has invalid artifact names: {row['case_id']}")
            for name in artifacts:
                copy_artifact(source, destination, name, max_artifact_bytes)
            copy_artifact(source, destination, "provenance/acceptance-cases.tsv",
                          max_artifact_bytes)
            roots.append((row["kind"], row["id"], row["case_id"], relative_root))
        record_path = staging / "provenance/acceptance-cases.tsv"
        with record_path.open("x", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        with (staging / cases.CASE_ROOT_PATH).open("x", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
            writer.writerow(cases.CASE_ROOT_HEADER)
            writer.writerows(roots)
        cases.validate_records(record_path, mapping, evidence_root=staging)
        resources.validate(record_path, staging)
        output.mkdir()
        for entry in staging.iterdir():
            os.rename(entry, output / entry.name)
        cases.validate_records(output / "provenance/acceptance-cases.tsv", mapping,
                               evidence_root=output)
        resources.validate(output / "provenance/acceptance-cases.tsv", output)
    finally:
        shutil.rmtree(staging)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("source_roots", type=Path, nargs="+")
    parser.add_argument("--manifest", type=Path, default=Path("docs/largefile-capabilities.tsv"))
    parser.add_argument("--map", dest="mapping", type=Path,
                        default=Path("docs/largefile-capability-case-map.tsv"))
    args = parser.parse_args(argv)
    try:
        mapping = cases.validate_map(args.manifest, args.mapping)
        output = assemble(args.output, args.source_roots, mapping)
    except (OSError, ValueError, csv.Error) as error:
        print(f"case bundle failed: {error}", file=sys.stderr)
        return 1
    print(f"case bundle validated: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
