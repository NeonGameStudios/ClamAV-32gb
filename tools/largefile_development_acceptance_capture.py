#!/usr/bin/env python3
"""Capture small, current-source clamscan records for the R04 schema.

This is a development evidence producer, not a release qualification gate.
It runs the supplied scanner against a deterministic local signature and binds
the file and stdin results to the structured reports, debug offsets, fixture,
database, build cache, and source manifest.  The release runner remains the
only path that can claim 32-GiB or certified-platform evidence.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import largefile_acceptance_cases as acceptance_cases
import largefile_runtime_acceptance_case_producer as runtime_producer


SIGNATURE = "LargeFile.R04.Runtime.Detection"
MARKER = b"CLAMAV-R04-RUNTIME-DETECTION"
PREFIX = b"R04-deterministic-prefix:"
MAX_SCAN_SIZE = 32 * 1024 * 1024 * 1024
POC_HEADER = [
    "file", "expected_offset", "expected_size", "actual_size", "size_matches",
    "scan_status", "detected", "signature_matches", "marker_at_expected",
    "engine_offset", "offset_matches", "tmp_bytes",
]


def fail(message: str) -> None:
    raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_file(path: Path, label: str) -> Path:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} is missing or symlinked: {path}")
    return path


def write_fixture(root: Path) -> tuple[Path, int]:
    fixture = root / "corpus/r04-runtime-detection.bin"
    fixture.parent.mkdir(parents=True, exist_ok=True)
    fixture.write_bytes(PREFIX + MARKER + b"\n")
    return fixture, len(PREFIX)


def write_database(root: Path) -> Path:
    database = root / "poc/db/largefile-poc.ndb"
    database.parent.mkdir(parents=True, exist_ok=True)
    encoded = MARKER.hex()
    database.write_text(f"{SIGNATURE}:0:*:{encoded}\n", encoding="utf-8")
    return database


def write_clean_database(root: Path) -> Path:
    database = root / "clean-db/clean-no-match.ndb"
    database.parent.mkdir(parents=True, exist_ok=True)
    database.write_text("Clean.NoMatch:0:*:deadbeef00\n", encoding="utf-8")
    return database


def run_case(
    scanner: Path,
    database: Path,
    fixture: Path,
    report: Path,
    log: Path,
    tempdir: Path,
    use_stdin: bool,
    cvd_certs_dir: Path | None,
    max_filesize: str = "32G",
) -> int:
    tempdir.mkdir(parents=True, exist_ok=True)
    report.parent.mkdir(parents=True, exist_ok=True)
    log.parent.mkdir(parents=True, exist_ok=True)
    command = [
        str(scanner),
        f"--database={database.parent}",
        f"--max-filesize={max_filesize}",
        "--max-scansize=32G",
        "--max-temporary-size=64G",
        "--max-contiguous-size=32G",
        "--pcre-max-filesize=32G",
        "--max-scantime=14400000",
        "--debug",
        "--no-summary",
        f"--report-json={report}",
        f"--tempdir={tempdir}",
        "-" if use_stdin else str(fixture),
    ]
    if cvd_certs_dir is not None:
        command.insert(-1, f"--cvdcertsdir={cvd_certs_dir}")
    with log.open("w", encoding="utf-8") as stream:
        if use_stdin:
            with fixture.open("rb") as input_stream:
                completed = subprocess.run(
                    command, stdin=input_stream, stdout=stream, stderr=subprocess.STDOUT,
                    check=False,
                )
        else:
            completed = subprocess.run(
                command, stdout=stream, stderr=subprocess.STDOUT, check=False,
            )
    return completed.returncode


def load_report(path: Path, label: str) -> dict:
    require_file(path, f"{label} report")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    if len(rows) != 1 or not isinstance(rows[0], dict):
        fail(f"{label} report is not one JSON object")
    return rows[0]


def validate_detection(report: dict, label: str, expected_size: int, offset: int) -> None:
    if report.get("version") != 1 or report.get("completion") != "DETECTION_TERMINATED":
        fail(f"{label} report is not a detection completion")
    if report.get("root_size") != expected_size or report.get("max_scan_size") != MAX_SCAN_SIZE:
        fail(f"{label} report does not bind the fixture size and scan budget")
    if report.get("last_alert") not in {SIGNATURE, f"{SIGNATURE}.UNOFFICIAL"}:
        fail(f"{label} report does not bind the exact signature")
    if report.get("last_alert_offset") != offset:
        fail(f"{label} report does not bind the exact marker offset")
    for field in runtime_producer.REPORT_FIELDS:
        value = report.get(field)
        if type(value) is not int or value < 0:
            fail(f"{label} report field {field} is not a non-negative integer")


def validate_log(path: Path, label: str, offset: int) -> None:
    text = require_file(path, f"{label} log").read_text(encoding="utf-8", errors="replace")
    if f"{SIGNATURE}.UNOFFICIAL" not in text and SIGNATURE not in text:
        fail(f"{label} log does not contain the exact signature")
    if "FOUND" not in text or f"matched at {offset}" not in text:
        fail(f"{label} log does not contain the exact detection offset")


def validate_clean_log(path: Path, label: str) -> None:
    text = require_file(path, f"{label} log").read_text(encoding="utf-8", errors="replace")
    if "FOUND" in text or "ERROR" in text or "OK" not in text:
        fail(f"{label} log does not prove a clean result")


def validate_limit_log(path: Path, label: str) -> None:
    text = require_file(path, f"{label} log").read_text(encoding="utf-8", errors="replace")
    if "Heuristics.Limits.Exceeded.MaxFileSize" not in text and "MaxFileSize" not in text:
        fail(f"{label} log does not contain the exact MaxFileSize diagnostic")
    if " FOUND" in text:
        fail(f"{label} limit log contains an unrelated detection")


def write_provenance(
    scanner: Path,
    root: Path,
    source_root: Path,
    build_dir: Path,
    fixture: Path,
    database: Path,
    offset: int,
    statuses: dict[str, int],
    reports: dict[str, Path],
    logs: dict[str, Path],
) -> None:
    provenance = root / "provenance"
    provenance.mkdir(parents=True, exist_ok=True)
    source_manifest = provenance / "source-manifest.txt"
    subprocess.run(
        [str(source_root / "tools/largefile_source_manifest.sh"), str(source_root), str(source_manifest)],
        check=True,
    )
    shutil.copyfile(require_file(build_dir / "CMakeCache.txt", "build CMakeCache.txt"),
                    provenance / "CMakeCache.txt")
    version = subprocess.run(
        [str(scanner)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, check=False,
    ).stdout.strip()
    (root / "build-identity.txt").write_text(
        "capture_kind=development-small-fixture\n"
        f"scanner_version={version}\n"
        f"platform={os.uname().sysname}-{os.uname().machine}\n"
        "rss_budget_kb=33554432\n"
        "pcre_rss_budget_kb=41943040\n"
        "post_pcre_rss_budget_kb=12582912\n"
        "max_temp_bytes=68719476736\n",
        encoding="utf-8",
    )
    corpus_manifest = root / "corpus/manifest.tsv"
    with corpus_manifest.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
        writer.writerow(["file", "marker", "expected_offset", "expected_size", "kind"])
        writer.writerow([
            fixture.name, MARKER.decode("ascii"), offset, fixture.stat().st_size,
            "development-detection",
        ])
    oracle = provenance / "runtime-acceptance-oracle.tsv"
    with oracle.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
        writer.writerow(runtime_producer.ORACLE_HEADER)
        writer.writerows([
            [
                "clamscan:file:clean-edge", "clamscan", "file",
                "corpus/r04-runtime-detection.bin", "clean/file.log",
                "clean/file.jsonl", fixture.stat().st_size, 0,
                "COMPLETE", "-", "-",
            ],
            [
                "clamscan:file:detection-edge", "clamscan", "file",
                "corpus/r04-runtime-detection.bin", "poc/logs/r04-runtime-detection.bin.log",
                "poc/reports/r04-runtime-detection.bin.jsonl", fixture.stat().st_size, 1,
                "DETECTION_TERMINATED", SIGNATURE, offset,
            ],
            [
                "clamscan:file:limit-edge", "clamscan", "file",
                "corpus/r04-runtime-detection.bin", "limit/file.log",
                "limit/file.jsonl", fixture.stat().st_size, 2,
                "LIMIT_INCOMPLETE", "-", "-",
            ],
            [
                "clamscan:stdin:clean-edge", "clamscan", "stdin",
                "corpus/r04-runtime-detection.bin", "clean/stdin.log",
                "clean/stdin.jsonl", fixture.stat().st_size, 0,
                "COMPLETE", "-", "-",
            ],
            [
                "clamscan:stdin:detection-edge", "clamscan", "stdin",
                "corpus/r04-runtime-detection.bin", "r04-runtime-detection-stdin.log",
                "reports/r04-runtime-detection-stdin.jsonl", fixture.stat().st_size, 1,
                "DETECTION_TERMINATED", SIGNATURE, offset,
            ],
            [
                "clamscan:stdin:limit-edge", "clamscan", "stdin",
                "corpus/r04-runtime-detection.bin", "limit/stdin.log",
                "limit/stdin.jsonl", fixture.stat().st_size, 2,
                "LIMIT_INCOMPLETE", "-", "-",
            ],
        ])
    status_file = provenance / "runtime-process-status.tsv"
    with status_file.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
        writer.writerow(runtime_producer.PROCESS_HEADER)
        for label, status in sorted(statuses.items()):
            writer.writerow([label, status])
    poc_results = root / "poc/results.tsv"
    poc_results.parent.mkdir(parents=True, exist_ok=True)
    with poc_results.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=POC_HEADER, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerow({
            "file": fixture.name,
            "expected_offset": offset,
            "expected_size": fixture.stat().st_size,
            "actual_size": fixture.stat().st_size,
            "size_matches": "yes",
            "scan_status": statuses["clamscan:file:detection-edge"],
            "detected": "yes",
            "signature_matches": "yes",
            "marker_at_expected": "yes",
            "engine_offset": offset,
            "offset_matches": "yes",
            "tmp_bytes": 0,
        })
    expected_size = fixture.stat().st_size
    runtime_producer.validate_clean(load_report(reports["file_clean"], "file clean"), "file clean", expected_size)
    validate_detection(load_report(reports["file"], "file detection"), "file detection", expected_size, offset)
    runtime_producer.validate_limit(load_report(reports["file_limit"], "file limit"), "file limit", expected_size)
    runtime_producer.validate_clean(load_report(reports["stdin_clean"], "stdin clean"), "stdin clean", expected_size)
    validate_detection(load_report(reports["stdin"], "stdin detection"), "stdin detection", expected_size, offset)
    runtime_producer.validate_limit(
        load_report(reports["stdin_limit"], "stdin limit"), "stdin limit", expected_size,
        allow_staged_root=True,
    )
    validate_clean_log(logs["file_clean"], "file clean")
    validate_log(logs["file"], "file detection", offset)
    validate_limit_log(logs["file_limit"], "file limit")
    validate_clean_log(logs["stdin_clean"], "stdin clean")
    validate_log(logs["stdin"], "stdin detection", offset)
    validate_limit_log(logs["stdin_limit"], "stdin limit")
    require_file(database, "development database")


def capture(
    scanner: Path,
    output: Path,
    source_root: Path,
    build_dir: Path,
    cvd_certs_dir: Path | None = None,
) -> int:
    scanner = require_file(scanner, "clamscan")
    if not os.access(scanner, os.X_OK):
        fail(f"clamscan is not executable: {scanner}")
    source_root = source_root.resolve()
    output = output.resolve()
    try:
        output.relative_to(source_root)
    except ValueError:
        pass
    else:
        fail("development evidence output must be outside the source tree")
    output.mkdir(parents=True, exist_ok=True)
    fixture, offset = write_fixture(output)
    database = write_database(output)
    write_clean_database(output)
    reports = {
        "file_clean": output / "clean/file.jsonl",
        "file": output / "poc/reports/r04-runtime-detection.bin.jsonl",
        "file_limit": output / "limit/file.jsonl",
        "stdin_clean": output / "clean/stdin.jsonl",
        "stdin": output / "reports/r04-runtime-detection-stdin.jsonl",
        "stdin_limit": output / "limit/stdin.jsonl",
    }
    logs = {
        "file_clean": output / "clean/file.log",
        "file": output / "poc/logs/r04-runtime-detection.bin.log",
        "file_limit": output / "limit/file.log",
        "stdin_clean": output / "clean/stdin.log",
        "stdin": output / "r04-runtime-detection-stdin.log",
        "stdin_limit": output / "limit/stdin.log",
    }
    statuses = {
        "clamscan:file:clean-edge": run_case(
            scanner, output / "clean-db/clean-no-match.ndb", fixture,
            reports["file_clean"], logs["file_clean"],
            output / "clean/tmp-file", False, cvd_certs_dir,
        ),
        "clamscan:file:detection-edge": run_case(
            scanner, database, fixture, reports["file"], logs["file"],
            output / "poc/tmp/r04-file", False,
            cvd_certs_dir,
        ),
        "clamscan:file:limit-edge": run_case(
            scanner, output / "clean-db/clean-no-match.ndb", fixture,
            reports["file_limit"], logs["file_limit"],
            output / "limit/tmp-file", False, cvd_certs_dir, "8",
        ),
        "clamscan:stdin:clean-edge": run_case(
            scanner, output / "clean-db/clean-no-match.ndb", fixture,
            reports["stdin_clean"], logs["stdin_clean"],
            output / "clean/tmp-stdin", True, cvd_certs_dir,
        ),
        "clamscan:stdin:detection-edge": run_case(
            scanner, database, fixture, reports["stdin"], logs["stdin"],
            output / "poc/tmp/r04-stdin", True,
            cvd_certs_dir,
        ),
        "clamscan:stdin:limit-edge": run_case(
            scanner, output / "clean-db/clean-no-match.ndb", fixture,
            reports["stdin_limit"], logs["stdin_limit"],
            output / "limit/tmp-stdin", True, cvd_certs_dir, "8",
        ),
    }
    write_provenance(
        scanner, output, source_root, build_dir, fixture, database, offset,
        statuses, reports, logs,
    )
    manifest = source_root / "docs/largefile-capabilities.tsv"
    mapping = source_root / "docs/largefile-capability-case-map.tsv"
    count = runtime_producer.produce(output, manifest, mapping, sanitizer="development")
    records = output / "provenance/acceptance-cases.tsv"
    acceptance_cases.validate_records(
        records, acceptance_cases.validate_map(manifest, mapping), evidence_root=output,
    )
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("clamscan", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--cvd-certs-dir", type=Path,
                        help="optional CVD root-CA directory for a build-tree scanner")
    args = parser.parse_args(argv)
    try:
        count = capture(
            args.clamscan, args.output, args.source_root, args.build_dir,
            args.cvd_certs_dir,
        )
        print(f"development acceptance capture wrote {count} R04 records")
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError, csv.Error, json.JSONDecodeError) as error:
        print(f"development acceptance capture failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
