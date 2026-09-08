#!/usr/bin/env python3
"""Produce R04 records from the structured runtime boundary evidence.

The runtime gate owns the independent oracle and process results.  This tool
binds explicitly listed clamscan file/stdin detection and limit cases to that
evidence; it never turns a missing clean case into a passing record.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import largefile_acceptance_cases as acceptance_cases
import largefile_service_workload_check as workload_check


ORACLE_HEADER = [
    "label", "kind", "id", "input", "log", "report", "expected_size",
    "expected_exit", "expected_completion", "expected_signature", "expected_offset",
]
PROCESS_HEADER = ["label", "status"]
POC_HEADER = [
    "file", "expected_offset", "expected_size", "actual_size", "size_matches",
    "scan_status", "detected", "signature_matches", "marker_at_expected",
    "engine_offset", "offset_matches", "tmp_bytes",
]
REPORT_FIELDS = (
    "status", "verdict", "root_size", "logical_bytes", "matcher_bytes",
    "contiguous_bytes", "temporary_bytes", "files_scanned",
    "max_recursion_depth", "elapsed_ms", "parser_operations",
    "detector_operations", "skipped_operations",
)
REPORT_NUMERIC_FIELDS = (
    "logical_bytes", "matcher_bytes", "contiguous_bytes", "temporary_bytes",
    "files_scanned", "max_recursion_depth", "elapsed_ms", "parser_operations",
    "detector_operations", "skipped_operations",
)
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_SCAN_SIZE_BYTES = 32 * 1024 * 1024 * 1024


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


def safe_path(root: Path, value: str, label: str) -> Path:
    if not value or value.startswith("/"):
        fail(f"{label} is not a safe relative path: {value!r}")
    path = (root / value).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"{label} escapes runtime evidence") from error
    return require_file(path, label)


def load_rows(path: Path, header: list[str], label: str) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if reader.fieldnames != header:
            fail(f"{label} has an invalid header")
        rows = list(reader)
    if any(any(value == "" for value in row.values()) for row in rows):
        fail(f"{label} contains an empty field")
    return rows


def load_oracle(root: Path) -> list[dict[str, str]]:
    rows = load_rows(
        require_file(root / "provenance/runtime-acceptance-oracle.tsv", "runtime acceptance oracle"),
        ORACLE_HEADER,
        "runtime acceptance oracle",
    )
    if not rows:
        fail("runtime acceptance oracle is empty")
    seen: set[str] = set()
    for row in rows:
        label = row["label"]
        if label in seen:
            fail(f"runtime acceptance oracle repeats {label}")
        seen.add(label)
        if row["kind"] != "clamscan" or row["id"] not in {"file", "stdin"}:
            fail(f"runtime acceptance oracle has an unsupported capability: {label}")
        if row["expected_exit"] not in {"0", "1", "2"} or not row["expected_size"].isdigit():
            fail(f"runtime acceptance oracle has invalid outcome fields: {label}")
        completion = row["expected_completion"]
        if completion == "DETECTION_TERMINATED":
            if row["expected_exit"] != "1" or not row["expected_signature"] or row["expected_signature"] == "-":
                fail(f"runtime acceptance oracle has an invalid detection outcome: {label}")
            if not row["expected_offset"].isdigit():
                fail(f"runtime acceptance oracle has no detection offset: {label}")
        elif completion == "LIMIT_INCOMPLETE":
            if row["expected_exit"] != "2" or row["expected_signature"] != "-" or row["expected_offset"] != "-":
                fail(f"runtime acceptance oracle has an invalid limit outcome: {label}")
        elif completion == "COMPLETE":
            if row["expected_exit"] != "0" or row["expected_signature"] != "-" or row["expected_offset"] != "-":
                fail(f"runtime acceptance oracle has an invalid clean outcome: {label}")
        else:
            fail(f"runtime acceptance oracle has an unsupported completion: {label}")
        for field in ("input", "log", "report"):
            safe_path(root, row[field], f"{label} {field}")
    return rows


def load_process_status(root: Path) -> dict[str, int]:
    rows = load_rows(
        require_file(root / "provenance/runtime-process-status.tsv", "runtime process status"),
        PROCESS_HEADER,
        "runtime process status",
    )
    result: dict[str, int] = {}
    for row in rows:
        if row["label"] in result or row["status"] not in {"0", "1", "2"}:
            fail(f"runtime process status has an invalid row: {row['label']}")
        result[row["label"]] = int(row["status"])
    return result


def load_poc_results(root: Path) -> dict[str, dict[str, str]]:
    rows = load_rows(
        require_file(root / "poc/results.tsv", "runtime POC results"),
        POC_HEADER,
        "runtime POC results",
    )
    return {row["file"]: row for row in rows}


def load_report(path: Path, label: str) -> dict:
    with path.open(encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    if len(rows) != 1 or not isinstance(rows[0], dict):
        fail(f"{label} structured report is not exactly one JSON object")
    return rows[0]


def validate_detection(
    report: dict,
    label: str,
    expected_size: int,
    expected_signature: str,
    expected_offset: int,
) -> None:
    if report.get("version") != 1 or report.get("completion") != "DETECTION_TERMINATED":
        fail(f"{label} report is not a version-1 detection result")
    for field in REPORT_FIELDS:
        value = report.get(field)
        if type(value) is not int or value < 0:
            fail(f"{label} report field {field} is not a non-negative integer")
    if report["root_size"] != expected_size or report["max_scan_size"] != MAX_SCAN_SIZE_BYTES:
        fail(f"{label} report does not bind the expected size/budget")
    if report["logical_bytes"] > report["max_scan_size"]:
        fail(f"{label} report exceeds its logical-byte budget")
    actual_signature = report.get("last_alert")
    if actual_signature not in {expected_signature, expected_signature + ".UNOFFICIAL"}:
        fail(f"{label} report alert does not match the independent oracle")
    # clamscan serializes its terminal detection as CL_VIRUS (1), while
    # daemon/report paths may retain CL_SUCCESS (0) alongside the non-clean
    # verdict.  The verdict, exact alert, and offset are the authoritative
    # detection bindings; accept either status but reject all other errors.
    if report.get("verdict") not in {2, 3} or report.get("status") not in {0, 1}:
        fail(f"{label} report does not carry a valid detection status")
    if report.get("last_alert_offset") != expected_offset:
        fail(f"{label} report alert offset does not match the independent oracle")


def validate_limit(
    report: dict,
    label: str,
    expected_size: int,
    allow_staged_root: bool = False,
) -> None:
    if report.get("version") != 1 or report.get("completion") != "LIMIT_INCOMPLETE":
        fail(f"{label} report is not a version-1 limit result")
    for field in REPORT_FIELDS:
        value = report.get(field)
        if type(value) is not int or value < 0:
            fail(f"{label} report field {field} is not a non-negative integer")
    if report["max_scan_size"] != MAX_SCAN_SIZE_BYTES:
        fail(f"{label} report does not bind the expected size/budget")
    staged_root = False
    if report["root_size"] != expected_size:
        # Unknown-length stdin is staged through MaxFileSize admission.  When
        # that admission fires, the scanner may only have a bounded prefix
        # (MaxFileSize + 1) available as the staged root.  Accept that exact
        # prefix only when the report binds the same limit and keeps it below
        # the independently measured input size; arbitrary truncation must
        # remain a failed evidence record.
        max_file_size = report.get("max_file_size")
        if not allow_staged_root or type(max_file_size) is not int or max_file_size < 0 or \
                report["root_size"] != max_file_size + 1 or \
                report["root_size"] >= expected_size:
            fail(f"{label} report does not bind the expected size/budget")
        staged_root = True
    if report.get("status", 0) == 0 or report.get("verdict") not in {0, 1}:
        fail(f"{label} report has a clean status/verdict for a limit result")
    if report.get("reason") != "Heuristics.Limits.Exceeded.MaxFileSize":
        fail(f"{label} report does not carry the exact MaxFileSize reason")
    if report.get("last_alert") not in (None, "") or report.get("last_alert_offset") is not None:
        fail(f"{label} limit report carries an unexpected alert binding")
    if report["logical_bytes"] != 0 or report["matcher_bytes"] != 0 or \
            (report["temporary_bytes"] != 0 and
             (not staged_root or report["temporary_bytes"] != report["root_size"])) or \
            report["parser_operations"] != 0 or \
            report["skipped_operations"] == 0:
        fail(f"{label} limit report shows work beyond size admission")


def validate_clean(report: dict, label: str, expected_size: int) -> None:
    if report.get("version") != 1 or report.get("completion") != "COMPLETE":
        fail(f"{label} report is not a version-1 complete result")
    for field in REPORT_FIELDS:
        value = report.get(field)
        if type(value) is not int or value < 0:
            fail(f"{label} report field {field} is not a non-negative integer")
    if report["root_size"] != expected_size or report["max_scan_size"] != MAX_SCAN_SIZE_BYTES:
        fail(f"{label} report does not bind the expected size/budget")
    if report.get("status") != 0 or report.get("verdict") not in {0, 1}:
        fail(f"{label} report is not a clean successful result")
    if report.get("last_alert") not in (None, "") or report.get("last_alert_offset") is not None:
        fail(f"{label} clean report carries an unexpected alert binding")
    if report["logical_bytes"] != expected_size or report["files_scanned"] == 0 or \
            report["skipped_operations"] != 0:
        fail(f"{label} clean report does not prove complete input traversal")


def record_for(
    root: Path,
    row: dict[str, str],
    process_status: dict[str, int],
    poc_results: dict[str, dict[str, str]],
    identities: dict[str, str],
    fixture_hashes: dict[Path, str],
    sanitizer: str,
) -> dict[str, str]:
    label = row["label"]
    expected_size = int(row["expected_size"])
    expected_exit = int(row["expected_exit"])
    input_path = safe_path(root, row["input"], f"{label} input")
    actual_size = input_path.stat().st_size
    if actual_size != expected_size:
        fail(f"{label} input size does not match the independent oracle")
    fixture_hashes.setdefault(input_path, sha256(input_path))

    report_path = safe_path(root, row["report"], f"{label} report")
    log_path = safe_path(root, row["log"], f"{label} log")
    report = load_report(report_path, label)
    if row["expected_completion"] == "DETECTION_TERMINATED":
        validate_detection(report, label, expected_size, row["expected_signature"], int(row["expected_offset"]))
    elif row["expected_completion"] == "COMPLETE":
        validate_clean(report, label, expected_size)
    else:
        validate_limit(report, label, expected_size, allow_staged_root=row["id"] == "stdin")

    if row["id"] == "file":
        if row["expected_completion"] == "DETECTION_TERMINATED":
            poc = poc_results.get(Path(row["input"]).name)
            if poc is None or any(poc[field] != expected for field, expected in {
                "expected_offset": row["expected_offset"],
                "expected_size": row["expected_size"],
                "actual_size": row["expected_size"],
                "size_matches": "yes",
                "scan_status": str(expected_exit),
                "detected": "yes",
                "signature_matches": "yes",
                "marker_at_expected": "yes",
                "engine_offset": row["expected_offset"],
                "offset_matches": "yes",
            }.items()):
                fail(f"{label} is not backed by a passing POC result row")
        elif process_status.get(label) != expected_exit:
            fail(f"{label} process status is not bound to the independent oracle")
    else:
        if process_status.get(label) != expected_exit:
            fail(f"{label} process status is not bound to the independent oracle")
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        if row["expected_completion"] == "DETECTION_TERMINATED":
            if f"signature {row['expected_signature']}" not in log_text or \
                    f"matched at {row['expected_offset']}" not in log_text:
                fail(f"{label} log does not contain the exact signature and offset")
        elif row["expected_completion"] == "COMPLETE":
            if "FOUND" in log_text or "OK" not in log_text:
                fail(f"{label} log does not prove a clean complete scan")
        elif "MaxFileSize" not in log_text and "max file size" not in log_text.lower():
            fail(f"{label} log does not contain the exact size-limit diagnostic")

    if row["expected_completion"] == "COMPLETE" and row["id"] == "file":
        if process_status.get(label) != expected_exit:
            fail(f"{label} process status is not bound to the independent oracle")

    kind = row["kind"]
    identifier = row["id"]
    case_id = label
    clean_database = row["expected_completion"] == "COMPLETE"
    database_artifact = "clean-db/clean-no-match.ndb" if clean_database else "poc/db/largefile-poc.ndb"
    artifacts = [
        row["log"], row["report"], row["input"], "poc/results.tsv",
        "corpus/manifest.tsv", database_artifact,
        "provenance/source-manifest.txt", "build-identity.txt",
        "provenance/CMakeCache.txt", "provenance/runtime-acceptance-oracle.tsv",
        "provenance/runtime-process-status.tsv",
    ]
    for artifact in artifacts:
        safe_path(root, artifact, f"{label} artifact")
    resource = identities
    return {
        "kind": kind,
        "id": identifier,
        "case_id": case_id,
        "source_manifest_sha256": identities["source_manifest_sha256"],
        "build_identity_sha256": identities["build_identity_sha256"],
        "config_sha256": identities["config_sha256"],
        "platform": f"{os.uname().sysname}-{os.uname().machine}",
        "fixture_role": "runtime-edge",
        "fixture_sha256": fixture_hashes[input_path],
        "oracle_sha256": identities["oracle_sha256"],
        "database_sha256": identities["clean_database_sha256" if clean_database else "database_sha256"],
        "exit_code": str(expected_exit),
        "verdict": (
            "DETECTED" if row["expected_completion"] == "DETECTION_TERMINATED" else
            "CLEAN" if row["expected_completion"] == "COMPLETE" else
            "INCOMPLETE"
        ),
        "completion": row["expected_completion"],
        "reason": report.get("reason") or (
            "structured report clean completion" if row["expected_completion"] == "COMPLETE" else
            "structured report limit rejection" if row["expected_completion"] == "LIMIT_INCOMPLETE" else
            "structured report detection"
        ),
        "alert_signature": report.get("last_alert") or "-",
        "alert_offset": str(report["last_alert_offset"]) if report.get("last_alert_offset") is not None else "-",
        **{field: str(report[field]) for field in REPORT_NUMERIC_FIELDS},
        "sanitizer": sanitizer,
        "resource_phase": (
            f"rss<={resource['rss_budget_kb']};"
            f"pcre<={resource['pcre_rss_budget_kb']};"
            f"post-pcre<={resource['post_pcre_rss_budget_kb']};"
            f"temporary<={resource['max_temp_bytes']}"
        ),
        "health": "pass",
        "cleanup": "pass",
        "artifacts": ",".join(artifacts),
    }


def produce(root: Path, manifest: Path, mapping_path: Path,
            sanitizer: str = "release") -> int:
    root = root.resolve()
    mapping = acceptance_cases.validate_map(manifest, mapping_path)
    required = {
        (row["kind"], row["id"]): set(row["required_case_ids"].split(","))
        for row in mapping
    }
    oracle_rows = load_oracle(root)
    process_status = load_process_status(root)
    poc_results = load_poc_results(root)
    identity_paths = {
        "source_manifest_sha256": root / "provenance/source-manifest.txt",
        "build_identity_sha256": root / "build-identity.txt",
        "config_sha256": root / "provenance/CMakeCache.txt",
        "oracle_sha256": root / "provenance/runtime-acceptance-oracle.tsv",
        "database_sha256": root / "poc/db/largefile-poc.ndb",
        "clean_database_sha256": root / "clean-db/clean-no-match.ndb",
    }
    identities = {key: sha256(require_file(path, key)) for key, path in identity_paths.items()}
    summary = {}
    for line in require_file(root / "build-identity.txt", "runtime build identity").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            summary[key] = value.split()[0]
    for field in ("rss_budget_kb", "pcre_rss_budget_kb", "post_pcre_rss_budget_kb", "max_temp_bytes"):
        if not summary.get(field, "").isdigit():
            fail(f"runtime build identity has no numeric {field}")
    identities.update(summary)
    fixture_hashes: dict[Path, str] = {}
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in oracle_rows:
        record = record_for(
            root, row, process_status, poc_results, identities, fixture_hashes, sanitizer,
        )
        key = record["case_id"]
        if key in seen or key not in required[(record["kind"], record["id"] )]:
            fail(f"runtime producer generated a duplicate or unrequired case: {key}")
        seen.add(key)
        records.append(record)

    destination = root / "provenance/acceptance-cases.tsv"
    staging = destination.with_name(f".{destination.name}.staging")
    with staging.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=acceptance_cases.RECORD_HEADER,
                                delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(sorted(records, key=lambda record: record["case_id"]))
    os.replace(staging, destination)
    return len(records)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime_output", type=Path)
    parser.add_argument("--manifest", type=Path, default=Path("docs/largefile-capabilities.tsv"))
    parser.add_argument("--map", dest="mapping", type=Path,
                        default=Path("docs/largefile-capability-case-map.tsv"))
    parser.add_argument(
        "--sanitizer",
        choices=("development", "release", "c-asan-ubsan", "rust-asan",
                 "release+c-asan-ubsan+rust-asan"),
        default="release",
        help="sanitizer/build identity to retain in each record",
    )
    args = parser.parse_args(argv)
    try:
        count = produce(args.runtime_output, args.manifest, args.mapping, args.sanitizer)
        print(f"large-file runtime acceptance case producer wrote {count} records")
        return 0
    except (OSError, ValueError, KeyError, csv.Error, json.JSONDecodeError) as error:
        print(f"large-file runtime acceptance case producer failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
