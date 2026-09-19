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
import os
import re
import stat
import sys
from pathlib import Path

import largefile_acceptance_cases as acceptance_cases
from largefile_service_oversize import validate_evidence as validate_oversize_evidence


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
KINDS = {"cli", "service", "report", "legacy", "milter", "oversize"}
LEGACY_MODES = {
    "edge_contscan": "CONTSCAN",
    "edge_multiscan": "MULTISCAN",
    "edge_allmatch": "ALLMATCHSCAN",
    "edge_fildes": "FILDES",
    "edge_instream": "INSTREAM",
}
MAX_LOGICAL_BYTES = 64 * 1024 * 1024 * 1024
EXACT_EDGE_BYTES = 32 * 1024 * 1024 * 1024
INPUT_ROLES = ("production", "materialized", "expansion", "edge")
# This is the SHA-256 of the exact official milter fixture: the three fixed
# headers, 32 GiB minus the marker of byte 0x5a ('Z'), and MARKER. The
# independent harness oracle derives the same value without materializing it.
MILTER_EXACT_STREAM_SHA256 = "7ec57c684966d38ba3db215be49cffa732317898dc8868439be681ba6ed6d50e"


def fail(message: str) -> None:
    raise RuntimeError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_outcome(label: str, exit_code: int, completion: str, signature: str) -> None:
    """Check the CLI outcome contract independently of an expected report.

    Detection wins over earlier incomplete operations in scan_report.c. It may
    therefore retain skipped operations, but must not be a clean/no-alert exit.
    """
    if completion == "COMPLETE":
        valid = exit_code == 0 and signature == "-"
    elif completion == "DETECTION_TERMINATED":
        valid = exit_code == 1 and signature != "-"
    elif completion in {"LIMIT_INCOMPLETE", "UNSUPPORTED", "MALFORMED_CONFIRMED",
                        "RESOURCE_FAILURE", "APPLICATION_ABORT"}:
        valid = exit_code == 2 and signature == "-"
    else:
        valid = False
    if not valid:
        fail(f"{label} has contradictory exit/completion/signature results")


def read_tsv(path: Path, header: list[str], label: str) -> list[list[str]]:
    try:
        with path.open(newline="", encoding="utf-8") as stream:
            reader = csv.reader(stream, delimiter="\t", strict=True)
            rows = []
            for line_number, row in enumerate(reader, start=1):
                if len(row) != len(header):
                    fail(
                        f"{label} has {len(row)} columns at line {line_number}; "
                        f"expected {len(header)}"
                    )
                if any(value == "" for value in row):
                    fail(f"{label} has an empty field at line {line_number}")
                rows.append(row)
    except csv.Error as error:
        fail(f"{label} has malformed TSV: {error}")
    if not rows or rows[0] != header:
        fail(f"{label} has an invalid header")
    return rows


def load_oracle(path: Path) -> dict[str, tuple[int, str, int, str, str, str, str]]:
    rows = read_tsv(path, ORACLE_HEADER, "qualification oracle")

    result = {}
    for line_number, row in enumerate(rows[1:], start=2):
        if len(row) != 8 or row[0] not in ROLES:
            fail(f"qualification oracle has an invalid row at line {line_number}")
        role, size, digest, exit_code, completion, signature, offset, file_type = row
        if role in result:
            fail(f"qualification oracle duplicates role {role}")
        if not size.isdigit() or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            fail(f"qualification oracle has an invalid input binding for {role}")
        validate_role_size(role, int(size))
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
        validate_outcome(f"{role} oracle", int(exit_code), completion, signature)
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
    # Keep clamdscan's supported mode combinations distinct from direct
    # legacy-wire probes.  The client-side flags select materially different
    # path, stream, and fd-passing behavior and must each bind their own
    # report-backed workload.
    for label in (
        "edge-clamdscan-multiscan",
        "edge-clamdscan-stream-multiscan",
        "edge-clamdscan-fdpass-multiscan",
    ):
        expected[label] = ("service", "edge", False)
    for label in ("edge_contscan", "edge_multiscan", "edge_allmatch", "edge_fildes", "edge_instream"):
        # These labels are direct clamd legacy-wire probes.  They must not be
        # accepted as clamdscan report-mode evidence merely because the client
        # happens to expose similarly named options.
        expected[label] = ("legacy", "edge", False)
    for client in (1, 2):
        expected[f"clamd-parallel-client-{client}"] = ("service", "edge", False)
    expected["milter-exact-edge"] = ("milter", "-", False)
    expected["oversize-fildesreport"] = ("oversize", "-", False)
    return expected


def evidence_path(out: Path, value: str, label: str, required: bool = True) -> Path | None:
    if value == "-" and not required:
        return None
    if not value or value.startswith("/"):
        fail(f"{label} must be a relative evidence path")
    try:
        return acceptance_cases.safe_evidence_file(out, value, label)
    except ValueError as error:
        if "escapes evidence root" in str(error):
            raise RuntimeError(f"{label} escapes the service evidence directory") from error
        fail(str(error))


def validate_role_size(role: str, size: int) -> None:
    if role not in ROLES:
        fail(f"workload has an invalid oracle role: {role}")
    if role == "edge" and size != EXACT_EDGE_BYTES:
        fail(f"edge input must be exactly {EXACT_EDGE_BYTES} bytes (32 GiB)")
    if role == "materialized" and size == 0:
        fail("materialized input must be nonempty")


def input_layout(stream, role: str, info: os.stat_result) -> tuple[int | None, int | None]:
    """Require filesystem-reported allocation and no reported holes.

    This is a conservative filesystem admission policy, not a claim of unique
    physical extents. Reflinks can share allocated data; SEEK_HOLE accuracy is
    filesystem-dependent. Unsupported allocation queries fail qualification.
    """
    blocks = getattr(info, "st_blocks", None)
    allocated = blocks * 512 if type(blocks) is int and blocks >= 0 else None
    if role not in {"materialized", "edge"}:
        return allocated, None
    if allocated is None or allocated < info.st_size:
        fail(f"{role} input is not fully allocated: {allocated} allocated bytes for {info.st_size} bytes")
    if not hasattr(os, "SEEK_HOLE"):
        fail(f"{role} input filesystem hole queries are unavailable")
    try:
        first_hole = os.lseek(stream.fileno(), 0, os.SEEK_HOLE)
        stream.seek(0)
    except OSError as error:
        raise RuntimeError(f"{role} input filesystem hole query failed: {error}") from error
    if first_hole != info.st_size:
        fail(f"{role} input contains a reported hole at {first_hole}, before EOF {info.st_size}")
    return allocated, first_hole


def input_identity(info: os.stat_result) -> tuple:
    # Reading can change atime. Size, ownership of the open inode, write times,
    # and allocation must remain stable while binding the fixture.
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, getattr(info, "st_blocks", None))


def input_binding(path_text: str, role: str, oracle: dict) -> dict:
    if role not in ROLES:
        fail(f"workload has an invalid oracle role: {role}")
    path = Path(path_text)
    expected_size, expected_hash, *_ = oracle[role]
    validate_role_size(role, expected_size)
    # O_NONBLOCK prevents a replaced fixture pathname from hanging on a FIFO.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            fail(f"workload input is not a regular file: {path}")
        if before.st_size != expected_size:
            fail(f"{role} input size changed: {before.st_size} != {expected_size}")
        allocated, first_hole = input_layout(stream, role, before)
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        if input_identity(before) != input_identity(os.fstat(stream.fileno())) or \
                input_identity(before) != input_identity(path.stat()):
            fail(f"{role} input changed while binding its contents: {path}")
        if digest.hexdigest() != expected_hash:
            fail(f"{role} input SHA-256 changed: {path}")
    return {"input": str(path.resolve()), "size": before.st_size,
            "sha256": digest.hexdigest(), "allocated_bytes": allocated,
            "first_hole": first_hole}


def input_evidence(out: Path) -> dict:
    records = []
    for phase in ("before", "after"):
        path = out / f"provenance/service-inputs-{phase}.json"
        with path.open(encoding="utf-8") as stream:
            record = acceptance_cases.load_json(
                stream.read(), f"service input {phase} evidence"
            )
        if not isinstance(record, dict) or record.get("version") != 1 or \
                not isinstance(record.get("inputs"), dict) or set(record["inputs"]) != ROLES:
            fail(f"service input {phase} evidence has an invalid schema")
        records.append(record["inputs"])
    if records[0] != records[1]:
        fail("service input allocation/content evidence changed during qualification")
    return records[0]


def load_report(path: Path, label: str) -> dict:
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"{label} has no structured report")
    with path.open(encoding="utf-8") as stream:
        rows = [acceptance_cases.load_json_object(line, label)
                for line in stream if line.strip()]
    if len(rows) != 1 or not isinstance(rows[0], dict):
        fail(f"{label} structured report is not exactly one JSON object")
    return rows[0]


def validate_report(report: dict, label: str, oracle_row: tuple) -> None:
    expected_size, _, expected_exit, expected_completion, expected_signature, expected_offset, expected_type = oracle_row
    validate_outcome(f"{label} oracle", expected_exit, expected_completion, expected_signature)
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
    if report.get("max_scan_size") != MAX_LOGICAL_BYTES:
        fail(f"{label} report max scan size is not the certified 64-GiB logical budget")
    if report["logical_bytes"] > report["max_scan_size"]:
        fail(f"{label} report exceeds its declared logical-byte budget")
    last_alert = report.get("last_alert")
    if expected_signature == "-":
        if last_alert not in (None, "") or report.get("verdict") not in (0, 1):
            fail(f"{label} clean report contains an unexpected alert or verdict")
        if report.get("last_alert_offset") is not None:
            fail(f"{label} clean report contains an unexpected alert offset")
    elif last_alert not in (expected_signature, f"{expected_signature}.UNOFFICIAL"):
        fail(f"{label} report alert does not exactly match the oracle")
    elif report.get("verdict") not in (2, 3):
        fail(f"{label} detection report does not carry a non-clean verdict")
    elif type(report.get("last_alert_offset")) is not int or report["last_alert_offset"] < 0:
        fail(f"{label} detection report does not carry a native-width alert offset")
    elif report["last_alert_offset"] != int(expected_offset):
        fail(f"{label} report alert offset does not exactly match the oracle")
    if expected_completion == "DETECTION_TERMINATED" and report["status"] not in (0, 1):
        fail(f"{label} report status is invalid for a detection")
    elif expected_completion == "COMPLETE" and report["status"] != 0:
        fail(f"{label} report status is non-success for expected clean exit")
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
    # Match the actual signature field of a FOUND line, not a substring in a
    # filename, a different signature, or an unrelated debug line.
    escaped = re.escape(expected_signature)
    if not expected_signature.endswith(".UNOFFICIAL"):
        escaped += r"(?:\.UNOFFICIAL)?"
    found = rf"^.*: {escaped}(?:\([0-9a-fA-F]+:[0-9]+\))? FOUND[ \t]*$"
    if re.search(found, text, re.MULTILINE) is None:
        fail(f"{label} text log does not contain the expected detection")
    if check_offset and expected_offset != "-":
        matches = re.findall(rf"(?:^|[ \t])signature {escaped} matched at ([0-9]+)(?=[ \t\r\n]|$)", text, re.MULTILINE)
        if expected_offset not in matches:
            fail(f"{label} text log does not contain the expected match offset")


def validate_report_log(path: Path, label: str, report: dict) -> None:
    """Validate a report frontend's outcome line without re-parsing its alert.

    A structured-report workload is explicitly typed in the workload manifest
    and its report has already been checked by ``validate_report``.  That
    report is therefore the authoritative exact alert/offset binding.  Some
    frontends intentionally print only ``target: FOUND``; requiring the exact
    alert name in this supplementary text log would reject that valid format.
    A bare FOUND line is accepted here only for this typed path, never as a
    substitute for structured-report validation.
    """
    if not path.is_file():
        fail(f"{label} has no text log")
    text = path.read_text(encoding="utf-8", errors="replace")
    completion = report.get("completion")
    if completion == "DETECTION_TERMINATED":
        if re.search(r"^.*: FOUND[ \t]*$", text, re.MULTILINE) is None:
            fail(f"{label} report log does not contain a complete detection outcome")
        return
    if completion == "COMPLETE":
        if "FOUND" in text:
            fail(f"{label} report log contains an unexpected detection")
        return
    if completion in {
        "LIMIT_INCOMPLETE",
        "UNSUPPORTED",
        "MALFORMED_CONFIRMED",
        "RESOURCE_FAILURE",
        "APPLICATION_ABORT",
    }:
        if "FOUND" in text or re.search(r"^.*: INCOMPLETE(?:[ \t(].*)?$", text, re.MULTILINE) is None:
            fail(f"{label} report log does not contain a clean incomplete outcome")
        return
    fail(f"{label} structured report has an unsupported completion")


def validate_process_status(label: str, status: int, oracle_row: tuple) -> None:
    expected_exit = oracle_row[2]
    if status != expected_exit:
        fail(f"{label} process status {status} does not match oracle {expected_exit}")


def validate_legacy_log(
    path: Path, label: str, oracle_row: tuple, expected_mode: str
) -> None:
    """Validate a direct legacy-wire reply without inventing report fields."""
    if not path.is_file():
        fail(f"{label} has no text log")
    text = path.read_text(encoding="utf-8", errors="replace")
    if re.search(rf"^protocol_mode={re.escape(expected_mode)}$", text, re.MULTILINE) is None:
        fail(f"{label} legacy log does not bind the expected {expected_mode} wire command")
    _, _, _, completion, _, _, _ = oracle_row
    if completion == "DETECTION_TERMINATED":
        validate_log(path, label, oracle_row, False)
    elif completion == "COMPLETE":
        if "FOUND" in text or re.search(r": OK[ \t]*$", text, re.MULTILINE) is None:
            fail(f"{label} legacy reply does not prove a clean result")
    elif completion == "LIMIT_INCOMPLETE":
        limit_text = text.lower()
        if "FOUND" in text or (
            "maxfilesize" not in limit_text
            and "max file size" not in limit_text
            and "size limit exceeded" not in limit_text
            and "exceeded max scan size" not in limit_text
        ):
            fail(f"{label} legacy reply does not prove the size-limit result")
        if "ERROR" not in text:
            fail(f"{label} legacy size-limit reply is not an error result")
    else:
        fail(f"{label} has unsupported legacy completion {completion}")


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
    if len(argv) == 6 and argv[0] == "--check-inputs":
        oracle = load_oracle(Path(argv[1]))
        records = {role: input_binding(path, role, oracle)
                   for role, path in zip(INPUT_ROLES, argv[2:])}
        print(json.dumps({"version": 1, "inputs": records}, sort_keys=True))
        return 0
    if len(argv) != 1:
        print("usage: largefile_service_workload_check.py SERVICE_OUTPUT\n"
              "   or: largefile_service_workload_check.py --check-inputs ORACLE PRODUCTION MATERIALIZED EXPANSION EDGE",
              file=sys.stderr)
        return 2
    out = Path(argv[0]).resolve()
    oracle_path = out / "provenance/qualification-oracle.tsv"
    workload_path = out / "provenance/service-workload-results.tsv"
    if not oracle_path.is_file() or not workload_path.is_file():
        fail("service workload evidence is missing its copied oracle or results manifest")
    oracle = load_oracle(oracle_path)
    validate_binding(out, oracle_path, workload_path)
    inputs = input_evidence(out)

    rows = read_tsv(workload_path, WORKLOAD_HEADER, "service workload results")
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

        if kind == "oversize":
            if input_path != "-" or status != 0:
                fail("oversize workload must be a successful probe with a removed fixture")
            evidence = evidence_path(out, report_path, f"{label} evidence")
            if evidence is None:
                fail("oversize workload has no rejection evidence")
            if log.read_text(encoding="utf-8").strip():
                fail("oversize workload emitted unexpected diagnostics")
            validate_oversize_evidence(load_report(evidence, label))
            continue

        if kind == "milter":
            if input_path != "-" or report_path != "-" or status != 0:
                fail("milter workload record is not a successful no-report record")
            text = log.read_text(encoding="utf-8", errors="replace")
            exact_wire = re.search(
                r"milter manual wire: body_bytes=(\d+) message_bytes=(\d+) "
                r"limit_bytes=(\d+) result=r "
                r"signature=Milter\.Protocol\.Test offset=(\d+) sha256=([0-9a-f]{64}) "
                r"completion=DETECTION_TERMINATED root_size=34359738368 "
                r"logical_bytes=(\d+) max_scan_size=68719476736 "
                r"skipped_operations=(\d+) last_alert_offset=(\d+)",
                text,
            )
            if exact_wire is None:
                fail("milter workload log does not prove the exact-edge rejection")
            if (
                exact_wire.group(1) != "34359738316"
                or exact_wire.group(2) != "34359738368"
                or exact_wire.group(3) != "34359738368"
                or exact_wire.group(4) != "34359738349"
                or exact_wire.group(6) != "34359738368"
                or exact_wire.group(7) != "0"
                or exact_wire.group(8) != "34359738349"
                or int(exact_wire.group(6)) > MAX_LOGICAL_BYTES
                or int(exact_wire.group(7)) < 0
            ):
                fail("milter workload log does not prove the exact-edge rejection")
            if exact_wire.group(5) != MILTER_EXACT_STREAM_SHA256:
                fail("milter workload log does not prove the deterministic transmitted stream digest")
            continue

        if kind == "legacy":
            if report_path != "-":
                fail(f"{label} legacy workload unexpectedly has a structured report")
            if input_binding(input_path, role, oracle) != inputs[role]:
                fail(f"{label} input does not match its recorded allocation/content evidence")
            expected_mode = LEGACY_MODES.get(label)
            if expected_mode is None:
                fail(f"{label} has no reviewed legacy wire command")
            validate_process_status(label, status, oracle[role])
            validate_legacy_log(log, label, oracle[role], expected_mode)
            continue

        if role not in ROLES:
            fail(f"service workload has an invalid role: {label}")
        if input_binding(input_path, role, oracle) != inputs[role]:
            fail(f"{label} input does not match its recorded allocation/content evidence")
        report = evidence_path(out, report_path, f"{label} report")
        if report is None:
            fail(f"{label} has no report path")
        report_record = load_report(report, label)
        validate_report(report_record, label, oracle[role])
        expected_exit = oracle[role][2]
        if kind == "report":
            if status != 0:
                fail(f"{label} protocol probe did not complete successfully")
            validate_report_log(log, label, report_record)
        elif status != expected_exit:
            fail(f"{label} process status {status} does not match oracle {expected_exit}")
        else:
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
