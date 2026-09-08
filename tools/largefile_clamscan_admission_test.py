#!/usr/bin/env python3
"""Exercise clamscan's small MaxFileSize admission cases through real CLI exit codes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile


MAX_SCAN_SIZE = 32 * 1024 * 1024 * 1024
MARKER = b"large-file-admission-regression"


def fail(message: str) -> None:
    raise AssertionError(message)


def run_case(
    scanner: Path,
    database: Path,
    fixture: Path,
    report: Path,
    tempdir: Path,
    source_root: Path,
    use_stdin: bool,
) -> subprocess.CompletedProcess[bytes]:
    tempdir.mkdir(parents=True, exist_ok=True)
    command = [
        str(scanner),
        f"--database={database}",
        "--max-filesize=8",
        f"--max-scansize={MAX_SCAN_SIZE}",
        "--max-temporary-size=64G",
        "--max-contiguous-size=32G",
        "--pcre-max-filesize=32G",
        "--debug",
        "--no-summary",
        f"--report-json={report}",
        f"--tempdir={tempdir}",
        f"--cvdcertsdir={source_root / 'unit_tests/input/signing/verify'}",
        "-" if use_stdin else str(fixture),
    ]
    return subprocess.run(
        command,
        input=fixture.read_bytes() if use_stdin else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def validate(report: Path, expected_root_size: int, expected_temporary: int) -> None:
    try:
        rows = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read structured report {report}: {error}")
    if len(rows) != 1 or not isinstance(rows[0], dict):
        fail(f"structured report is not exactly one object: {report}")
    result = rows[0]
    if result.get("completion") != "LIMIT_INCOMPLETE" or \
            result.get("reason") != "Heuristics.Limits.Exceeded.MaxFileSize":
        fail(f"report does not bind the MaxFileSize limit outcome: {result}")
    if result.get("max_file_size") != 8 or result.get("max_scan_size") != MAX_SCAN_SIZE:
        fail(f"report does not bind the configured limits: {result}")
    if result.get("root_size") != expected_root_size or \
            result.get("temporary_bytes") != expected_temporary or \
            result.get("logical_bytes") != 0 or result.get("matcher_bytes") != 0 or \
            result.get("parser_operations") != 0 or result.get("skipped_operations") == 0:
        fail(f"report has incorrect admission accounting: {result}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scanner", type=Path)
    parser.add_argument("source_root", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="clamav-admission-regression-") as name:
        root = Path(name)
        fixture = root / "fixture.bin"
        fixture.write_bytes(b"prefix:" + MARKER + b"\n")
        database = root / "db"
        database.mkdir()
        (database / "clean.ndb").write_text(
            "Clean.NoMatch:0:*:deadbeef00\n", encoding="utf-8"
        )
        file_report = root / "file.jsonl"
        file_result = run_case(
            args.scanner, database, fixture, file_report, root / "file-tmp",
            args.source_root, False,
        )
        if file_result.returncode != 2:
            fail(f"file MaxFileSize returned {file_result.returncode}, expected 2")
        validate(file_report, fixture.stat().st_size, 0)

        stdin_report = root / "stdin.jsonl"
        stdin_result = run_case(
            args.scanner, database, fixture, stdin_report, root / "stdin-tmp",
            args.source_root, True,
        )
        if stdin_result.returncode != 2:
            fail(f"stdin MaxFileSize returned {stdin_result.returncode}, expected 2\n{stdin_result.stdout.decode(errors='replace')}")
        validate(stdin_report, 9, 9)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, subprocess.SubprocessError) as error:
        print(f"large-file clamscan admission regression failed: {error}")
        raise SystemExit(1)
