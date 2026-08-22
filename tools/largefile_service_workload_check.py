#!/usr/bin/env python3
"""Independently verify the semantic workload records from service qualification.

The service gate validates each result while it is running.  This verifier is
run after the gate and rechecks the copied oracle, every recorded input, every
structured report, and the relevant text-log outcome.  It deliberately uses
only Python's standard library so it can run on the evidence host without
installing another dependency.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from pathlib import Path


ORACLE_HEADER = [
    "role",
    "expected_size",
    "expected_sha256",
    "expected_exit",
    "expected_completion",
    "expected_signature",
    "expected_offset",
    "expected_type",
]
WORKLOAD_HEADER = [
    "label",
    "kind",
    "role",
    "input",
    "log",
    "report",
    "status",
    "check_offset",
]
REPORT_FIELDS = (
    "status",
    "verdict",
    "root_size",
    "logical_bytes",
    "matcher_bytes",
    "contiguous_bytes",
    "temporary_bytes",
    "files_scanned",
    "max_recursion_depth",
    "elapsed_ms",
    "parser_operations",
    "detector_operations",
    "skipped_operations",
)
ROLES = {"production", "materialized", "expansion", "edge"}
KINDS = {"cli", "service", "report", "milter"}


def fail(message: str) -> None:
    raise RuntimeError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_oracle(path: Path) -> dict[str, tuple[int, str, int, str, str, str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.reader(stream, delimiter="\t"))
    if not rows or rows[0] != ORACLE_HEADER:
        fail("qualification oracle has an invalid header")

    result = {}
    for line_number, row in enumerate(rows[1:], start=2):
        if len(row) != 8 or row[0] not in ROLES:
            fail(f"qualification oracle has an invalid row at line {line_number}")
        role, size, digest, exit_code, completion, signature, offset, file_type = row
        if role in result:
            fail(f"qualification oracle duplicates role {role}")
        if not size.isdigit() or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            fail(f"qualification oracle has an invalid input binding for {role}")
        if exit_code not in {"0", "1", "2"}:
            fail(f"qualification oracle has an invalid exit for {role}")
        if completion not in {
            "COMPLETE",
            "DETECTION_TERMINATED",
            "LIMIT_INCOMPLETE",
            "UNSUPPORTED",
            "MALFORMED_CONFIRMED",
            "RESOURCE_FAILURE",
            "APPLICATION_ABORT",
        }:
            fail(f"qualification oracle has an invalid completion for {role}")
        if not signature or (signature == "-" and offset != "-"):
            fail(f"qualification oracle has an invalid signature binding for {role}")
        if signature != "-" and not offset.isdigit():
            fail(f"qualification oracle has an invalid offset binding for {role}")
        if not re.fullmatch(r"CL_TYPE_[A-Z0-9_]+", file_type):
            fail(f"qualification oracle has an invalid type binding for {role}")
        result[role] = (int(size), digest.lower(), int(exit_code), completion, signature, offset, file_type)
    if set(result) != ROLES:
        fail("qualification oracle does not contain exactly the four required roles")
    return result


def expected_workloads() -> dict[str, tuple[str, str, bool]]:
    expected = {}

    for mode in ("scanreport", "contscanreport", "multiscanreport", "allmatchscan", "fildesreport", "instreamreport"):
        expected[f"production_cvd_{mode}"] = ("report", "production", False)
    expected["production-clamscan"] = ("cli", "production", True)
    for worker in (1, 2):
        expected[f"clamd-serial-queue-{worker}"] = ("service", "materialized", False)
    for label, role in (
        ("production_cvd", "production"),
        ("production_cvd_fildes", "production"),
        ("production_cvd_instream", "production"),
        ("materialized_warm", "materialized"),
        ("materialized_cold", "materialized"),
        ("parser_expansion", "expansion"),
    ):
        expected[label] = ("service", role, False)
    expected["edge-clamscan"] = ("cli", "edge", True)
    expected["edge-clamscan-stdin"] = ("cli", "edge", True)
    expected["edge-clamdscan-stdin"] = ("service", "edge", False)
    for label in ("edge_contscan", "edge_multiscan", "edge_allmatch", "edge_fildes", "edge_instream"):
        expected[label] = ("service", "edge", False)
    for worker in (1, 2, 3, 4):
        expected[f"clamd-multiworker-{worker}"] = ("service", "edge", False)
    expected["milter-exact-edge"] = ("milter", "-", False)
    return expected


def evidence_path(out: Path, value: str, label: str, required: bool = True) -> Path | None:
    if value == "-" and not required:
        return None
    if not value or value.startswith("/"):
        fail(f"{label} must be a relative evidence path")
    candidate = (out / value).resolve()
    try:
        candidate.relative_to(out.resolve())
    except ValueError as error:
        raise RuntimeError(f"{label} escapes the service evidence directory") from error
    return candidate


def input_binding(path_text: str, role: str, oracle: dict) -> None:
    if role not in ROLES:
        fail(f"workload has an invalid oracle role: {role}")
    path = Path(path_text)
    if not path.is_file():
        fail(f"workload input is not a regular file: {path}")
    expected_size, expected_hash, *_ = oracle[role]
    actual_size = path.stat().st_size
    if actual_size != expected_size:
        fail(f"{role} input size changed: {actual_size} != {expected_size}")
    if sha256(path) != expected_hash:
        fail(f"{role} input SHA-256 changed: {path}")


def load_report(path: Path, label: str) -> dict:
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"{label} has no structured report")
    with path.open(encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    if len(rows) != 1 or not isinstance(rows[0], dict):
        fail(f"{label} structured report is not exactly one JSON object")
    return rows[0]


def validate_report(report: dict, label: str, oracle_row: tuple) -> None:
    expected_size, _, expected_exit, expected_completion, expected_signature, _, expected_type = oracle_row
    if report.get("version") != 1:
        fail(f"{label} report schema version is not 1")
    if report.get("completion") != expected_completion:
        fail(f"{label} report completion does not match the oracle")
    if report.get("file_type") != expected_type:
        fail(f"{label} report file type does not match the oracle")
    for field in REPORT_FIELDS:
        value = report.get(field)
        if type(value) is not int or value < 0:
            fail(f"{label} report field {field} is not a non-negative integer")
    if report["root_size"] != expected_size:
        fail(f"{label} report root size does not match the oracle")
    last_alert = report.get("last_alert")
    if expected_signature == "-":
        if last_alert not in (None, "") or report.get("verdict") not in (0, 1):
            fail(f"{label} clean report contains an unexpected alert or verdict")
    elif last_alert not in (expected_signature, f"{expected_signature}.UNOFFICIAL"):
        fail(f"{label} report alert does not exactly match the oracle")
    elif report.get("verdict") not in (2, 3):
        fail(f"{label} detection report does not carry a non-clean verdict")
    if expected_exit in (0, 1) and report["status"] != 0:
        fail(f"{label} report status is non-success for expected exit {expected_exit}")
    if expected_exit == 2 and report["status"] == 0:
        fail(f"{label} report status is clean for expected error exit 2")
    if expected_completion == "COMPLETE" and (
        report["status"] != 0
        or report.get("verdict") not in (0, 1)
        or report["skipped_operations"] != 0
    ):
        fail(f"{label} complete report is not complete and successful")


def validate_log(path: Path, label: str, oracle_row: tuple, check_offset: bool) -> None:
    if not path.is_file():
        fail(f"{label} has no text log")
    text = path.read_text(encoding="utf-8", errors="replace")
    _, _, _, _, expected_signature, expected_offset, _ = oracle_row
    if expected_signature == "-":
        if "FOUND" in text:
            fail(f"{label} text log contains an unexpected detection")
        return
    if expected_signature not in text or "FOUND" not in text:
        fail(f"{label} text log does not contain the expected detection")
    if check_offset and expected_offset != "-":
        escaped = re.escape(expected_signature)
        matches = re.findall(rf"signature {escaped}(?:\.UNOFFICIAL)? matched at ([0-9]+)", text)
        if expected_offset not in matches:
            fail(f"{label} text log does not contain the expected match offset")


def validate_binding(out: Path, oracle_path: Path, workload_path: Path) -> None:
    binding = out / "oracle-binding.txt"
    if not binding.is_file():
        fail("missing oracle-binding.txt")
    fields = {}
    for line in binding.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in fields:
            fail(f"oracle binding duplicates field {key}")
        fields[key] = value
    expected_oracle = "provenance/qualification-oracle.tsv"
    expected_workloads = "provenance/service-workload-results.tsv"
    if fields.get("qualification_oracle") != expected_oracle:
        fail("oracle binding does not reference the copied qualification oracle")
    if fields.get("workload_results") != expected_workloads:
        fail("oracle binding does not reference workload results")
    if fields.get("qualification_oracle_sha256") != sha256(oracle_path):
        fail("oracle binding hash does not match the copied qualification oracle")
    if fields.get("workload_results_sha256") != sha256(workload_path):
        fail("oracle binding hash does not match workload results")


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: largefile_service_workload_check.py SERVICE_OUTPUT", file=sys.stderr)
        return 2
    out = Path(argv[0]).resolve()
    oracle_path = out / "provenance/qualification-oracle.tsv"
    workload_path = out / "provenance/service-workload-results.tsv"
    if not oracle_path.is_file() or not workload_path.is_file():
        fail("service workload evidence is missing its copied oracle or results manifest")
    oracle = load_oracle(oracle_path)
    validate_binding(out, oracle_path, workload_path)

    with workload_path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.reader(stream, delimiter="\t"))
    if not rows or rows[0] != WORKLOAD_HEADER:
        fail("service workload results have an invalid header")
    expected = expected_workloads()
    seen = set()
    for line_number, row in enumerate(rows[1:], start=2):
        if len(row) != len(WORKLOAD_HEADER):
            fail(f"service workload results have an invalid row at line {line_number}")
        label, kind, role, input_path, log_path, report_path, status_text, offset_check = row
        if label in seen:
            fail(f"service workload results duplicate label {label}")
        seen.add(label)
        if label not in expected:
            fail(f"service workload results contain an unexpected label: {label}")
        expected_kind, expected_role, expected_offset_check = expected[label]
        if (kind, role, offset_check == "yes") != (expected_kind, expected_role, expected_offset_check):
            fail(f"service workload metadata does not match the expected shape: {label}")
        if status_text not in {"0", "1", "2"}:
            fail(f"service workload status is invalid: {label}")
        status = int(status_text)
        log = evidence_path(out, log_path, f"{label} log")
        if log is None:
            fail(f"{label} has no log path")

        if kind == "milter":
            if input_path != "-" or report_path != "-" or status != 0:
                fail("milter workload record is not a successful no-report record")
            text = log.read_text(encoding="utf-8", errors="replace")
            if (
                "milter manual wire:" not in text
                or "limit_bytes=34359738368" not in text
                or "result=r" not in text
            ):
                fail("milter workload log does not prove the exact-edge rejection")
            continue

        if role not in ROLES:
            fail(f"service workload has an invalid role: {label}")
        input_binding(input_path, role, oracle)
        report = evidence_path(out, report_path, f"{label} report")
        if report is None:
            fail(f"{label} has no report path")
        validate_report(load_report(report, label), label, oracle[role])
        expected_exit = oracle[role][2]
        if kind == "report":
            if status != 0:
                fail(f"{label} protocol probe did not complete successfully")
        elif status != expected_exit:
            fail(f"{label} process status {status} does not match oracle {expected_exit}")
        validate_log(log, label, oracle[role], offset_check == "yes")

    if seen != set(expected):
        missing = ", ".join(sorted(set(expected) - seen))
        fail(f"service workload results are missing required records: {missing}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"large-file service workload verification failed: {error}", file=sys.stderr)
        sys.exit(1)
