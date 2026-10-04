#!/usr/bin/env python3
"""Validate capability-specific large-file acceptance mappings and records.

The capability manifest remains the source of truth for coverage.  This tool
adds the R04 case-binding layer: every capability must have named, distinct
cases, and every recorded result must identify the exact capability/case,
fixture/oracle, build, resource, health, and cleanup evidence it represents.
It intentionally permits an empty records file while the certified runner is
unavailable; an empty file is a schema-valid, qualification-incomplete state.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MANIFEST_HEADER = ["kind", "id", "status", "source", "evidence_or_required_work"]
MAP_HEADER = ["kind", "id", "required_case_ids"]
RECORD_HEADER = [
    "kind", "id", "case_id", "source_manifest_sha256", "build_identity_sha256",
    "config_sha256", "platform", "fixture_role", "fixture_sha256", "oracle_sha256",
    "database_sha256", "exit_code", "verdict", "completion", "reason",
    "alert_signature", "alert_offset", "alert_offset_scope",
    "alert_offset_source", "alert_offset_evidence", "logical_bytes", "matcher_bytes",
    "contiguous_bytes", "temporary_bytes", "files_scanned", "max_recursion_depth",
    "elapsed_ms", "parser_operations", "detector_operations", "skipped_operations",
    "sanitizer", "resource_phase", "health", "cleanup", "artifacts",
]
CASE_ROOT_HEADER = ["kind", "id", "case_id", "relative_root"]
CASE_ROOT_PATH = "provenance/case-evidence-roots.tsv"

HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
CASE_ID_RE = re.compile(r"[a-z0-9_-]+:[^\t,]+:[a-z0-9_-]+\Z")
NONNEGATIVE_RE = re.compile(r"[0-9]+\Z")
RESOURCE_PHASE_TOKEN_RE = re.compile(
    r"(?:"
    r"(?P<measured>rss|pcre|post-pcre|temporary)(?:<=|<)[0-9]+(?:[A-Za-z]+)?|"
    r"(?P<development>max-file|max-scan|max-temp)=[0-9]+(?:[A-Za-z]+)?|"
    r"development-envelope|mode=[A-Za-z0-9_.:/+\\-]+|"
    r"resource-records=[0-9a-f]{64}|"
    r"daemon-rss=unmeasured|socket=tempfs|"
    r"daemon-health=ping-before-and-after|cleanup=lifecycle-verified"
    r")\Z"
)
RESOURCE_PHASE_BUDGETS = {
    "rss": ("<=", 32 * 1024 * 1024),
    "pcre": ("<=", 40 * 1024 * 1024),
    "post-pcre": ("<", 12 * 1024 * 1024),
    "temporary": ("<=", 64 * 1024 * 1024 * 1024),
}
REQUIRED_UNSUPPORTED = {
    ("matcher", "rust-fuzzy-image-ffi-admission"),
    ("matcher", "fuzzy-image"),
    ("parser", "CL_TYPE_AI_MODEL"),
    ("parser", "CL_TYPE_IGNORED"),
    ("parser", "CL_TYPE_PYTHON_COMPILED"),
    ("parser", "CL_TYPE_RAR"),
    ("parser", "CL_TYPE_RARSFX"),
}
# Case IDs are generated from reviewed routing rules, but the ID alone must
# not become a free-form label.  Keep the outcome contract beside the case
# schema so a copied generic proof cannot qualify a contradictory result.
CASE_COMPLETION_CONTRACTS = {
    "complete": {"COMPLETE"},
    "enabled": {"COMPLETE", "DETECTION_TERMINATED"},
    "clean-edge": {"COMPLETE"},
    "detection-edge": {"DETECTION_TERMINATED"},
    "limit-edge": {"LIMIT_INCOMPLETE"},
    # On-access permission has additional fail-closed outcomes beyond the
    # common ingress trio; R13 verifies these with real fanotify events.
    "resource-edge": {"RESOURCE_FAILURE"},
    # A configured MaxScanTime deadline is a limit result; APPLICATION_ABORT
    # is reserved for explicit cancellation without a configured limit.
    "timeout-edge": {"LIMIT_INCOMPLETE"},
    "parser-edge": {"MALFORMED_CONFIRMED"},
    "valid-complete": {"COMPLETE"},
    "late-detection": {"DETECTION_TERMINATED"},
    "malformed-confirmed": {"MALFORMED_CONFIRMED"},
    "limit": {"LIMIT_INCOMPLETE"},
    "exact-tail": {"DETECTION_TERMINATED"},
    "fault": {"RESOURCE_FAILURE", "APPLICATION_ABORT"},
    "unsupported-policy": {"UNSUPPORTED"},
    "disabled-or-rejection": {
        "UNSUPPORTED", "LIMIT_INCOMPLETE", "MALFORMED_CONFIRMED",
        "RESOURCE_FAILURE", "APPLICATION_ABORT",
    },
    "required-behavior": {"COMPLETE", "DETECTION_TERMINATED"},
    # R09's behavior case is intentionally format-specific; its paired
    # failure case is not allowed to look clean or detected.
    "required-failure": {
        "LIMIT_INCOMPLETE", "UNSUPPORTED", "MALFORMED_CONFIRMED",
        "RESOURCE_FAILURE", "APPLICATION_ABORT",
    },
}
# R09 keeps these focused unsupported/required behaviors separate from the
# general capability matrix.  A release record must bind both the behavior
# check and the required failure outcome before R09 can be closed.
R09_REQUIRED_CAPABILITIES = tuple(sorted(REQUIRED_UNSUPPORTED))
INGRESS_KINDS = {"clamd", "clamdscan", "clamscan", "milter", "on-access"}
SERVICE_LIFECYCLE_HEADER = ["event", "result"]
SERVICE_LIFECYCLE_MARKER = "daemon-health=ping-before-and-after;cleanup=lifecycle-verified"
SERVICE_LIFECYCLE_EXPECTED = {
    "ping_before_cases": "pass",
    "ping_after_cases": "pass",
    "pidfile_present_after_start": "yes",
    "daemon_running_before_stop": "yes",
    "daemon_exited_after_stop": "yes",
    "socket_absent_after_stop": "yes",
    "pidfile_absent_after_stop": "yes",
}


def fail(message: str) -> None:
    raise ValueError(message)


def load_json(value: str, label: str):
    """Parse one structured JSON value without accepting duplicate keys."""
    def reject_duplicate_keys(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                fail(f"{label} has duplicate JSON key: {key}")
            result[key] = item
        return result

    try:
        result = json.loads(value, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as error:
        fail(f"{label} has invalid JSON: {error}")
    return result


def load_json_object(value: str, label: str) -> dict:
    """Parse one structured evidence object without accepting duplicate keys."""
    result = load_json(value, label)
    if not isinstance(result, dict):
        fail(f"{label} is not a JSON object")
    return result


def parse_resource_phases(value: str, line_number: int) -> set[str]:
    """Parse the reviewed resource-phase grammar without ignoring junk."""
    tokens = value.split(";")
    if not tokens or any(not token for token in tokens):
        fail(
            f"acceptance record has an invalid resource phase token and lacks "
            f"structured resource phases at line {line_number}"
        )
    phases: set[str] = set()
    for token in tokens:
        match = RESOURCE_PHASE_TOKEN_RE.fullmatch(token)
        if match is None:
            fail(
                f"acceptance record has an invalid resource phase token and lacks "
                f"structured resource phases at line {line_number}: {token!r}"
            )
        phase = match.group("measured") or match.group("development")
        if phase in RESOURCE_PHASE_BUDGETS:
            budget_match = re.fullmatch(
                r"(?P<phase>rss|pcre|post-pcre|temporary)"
                r"(?P<operator><=|<)(?P<value>[0-9]+)",
                token,
            )
            if budget_match is None:
                fail(
                    f"acceptance record has an invalid measured resource phase "
                    f"at line {line_number}: {token!r}"
                )
            expected_operator, expected_value = RESOURCE_PHASE_BUDGETS[phase]
            actual_operator = budget_match.group("operator")
            actual_value = int(budget_match.group("value"))
            if actual_operator != expected_operator or actual_value > expected_value:
                fail(
                    f"acceptance record exceeds the {phase} resource budget "
                    f"at line {line_number}: {token!r}"
                )
        if phase is not None and phase in phases:
            fail(
                f"acceptance record repeats resource phase {phase} at line "
                f"{line_number}"
            )
        if phase is not None:
            phases.add(phase)
    return phases


def case_completion_contract(case_id: str) -> set[str] | None:
    """Return the allowed completion states for the reviewed case suffix."""
    suffix = case_id.rsplit(":", 1)[-1]
    return CASE_COMPLETION_CONTRACTS.get(suffix)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_service_fixture(
    identity: dict, expected_sha256: str, role: str,
    label: str = "service input",
) -> None:
    """Rehash an actual bound input, not just its retained JSON label."""
    source = identity.get("input")
    expected_size = identity.get("size")
    expected_allocated = identity.get("allocated_bytes")
    expected_hole = identity.get("first_hole")
    if not isinstance(source, str) or not source or not Path(source).is_absolute() or \
            ".." in Path(source).parts or type(expected_size) is not int or expected_size < 0 or \
            not isinstance(identity.get("sha256"), str) or \
            not HASH_RE.fullmatch(identity["sha256"]) or \
            identity["sha256"] != expected_sha256 or \
            (expected_allocated is not None and
             (type(expected_allocated) is not int or expected_allocated < 0)) or \
            (expected_hole is not None and
             (type(expected_hole) is not int or expected_hole < 0)):
        fail(f"{label} identity evidence is malformed for {role}")
    path = Path(source)
    # The final input must not be a symlink. Ancestor aliases such as macOS
    # /var -> /private/var are valid when the opened file is content-verified.
    if path.is_symlink():
        fail(f"{label} fixture is symlinked for {role}: {path}")
    if not path.is_file():
        fail(f"{label} fixture is missing or not a file for {role}: {path}")
    if expected_size >= 32 * 1024 * 1024 * 1024 and \
            (expected_allocated is None or expected_allocated < expected_size or
             expected_hole != expected_size):
        fail(f"{label} fixture lacks materialized exact-edge evidence for {role}")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
            fail(f"{label} fixture size/type changed for {role}")
        allocated = before.st_blocks * 512
        if expected_allocated is not None and allocated != expected_allocated:
            fail(f"{label} fixture allocation changed for {role}")
        if expected_hole is not None:
            try:
                first_hole = os.lseek(stream.fileno(), 0, os.SEEK_HOLE)
            except OSError as error:
                raise ValueError(f"{label} fixture hole check failed for {role}") from error
            if first_hole != expected_hole:
                fail(f"{label} fixture hole layout changed for {role}")
            stream.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        path_after = os.stat(path, follow_symlinks=False)
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_blocks")
    if any(getattr(before, field) != getattr(after, field) or
           getattr(before, field) != getattr(path_after, field)
           for field in stable_fields):
        fail(f"{label} fixture changed during verification for {role}")
    if digest.hexdigest() != expected_sha256:
        fail(f"{label} fixture content does not match its recorded SHA-256 for {role}")


def verify_direct_scan_artifacts(
    row: dict[str, str], identity: dict, artifact_names: set[str], root: Path,
    line_number: int,
) -> None:
    """Bind a copy-free direct-file record to its actual report and scan log."""
    report_name = "scan-report.jsonl"
    log_name = "provenance/scan.log"
    if report_name not in artifact_names or log_name not in artifact_names:
        fail(f"direct scan record lacks its report or scan log at line {line_number}")
    report_path = safe_evidence_file(root, report_name, "direct scan report")
    log_path = safe_evidence_file(root, log_name, "direct scan log")
    reports = [line for line in report_path.read_text(encoding="utf-8").splitlines()
               if line.strip()]
    if len(reports) != 1:
        fail(f"direct scan report is not exactly one object at line {line_number}")
    report = load_json_object(reports[0], "direct scan report")
    oracle_path = safe_evidence_file(root, "provenance/direct-oracle.json", "direct scan oracle")
    if "provenance/direct-oracle.json" not in artifact_names:
        fail(f"direct scan record does not retain its independent oracle at line {line_number}")
    oracle = load_json_object(oracle_path.read_text(encoding="utf-8"), "direct scan oracle")
    if oracle.get("case_id") != row["case_id"] or \
            oracle.get("alert_signature", "-") != row["alert_signature"] or \
            oracle.get("alert_offset") != (
                int(row["alert_offset"]) if row["completion"] == "DETECTION_TERMINATED" else None
            ) or oracle.get("alert_offset_scope") != row["alert_offset_scope"] or \
            sha256(oracle_path) != row["oracle_sha256"]:
        fail(f"direct scan record offset binding differs from its independent oracle at line {line_number}")
    source = identity["input"]
    if row["sanitizer"] != "development":
        expected_size = 32 * 1024 * 1024 * 1024
        if row["completion"] == "LIMIT_INCOMPLETE":
            expected_size += 1
        if identity["size"] != expected_size:
            fail(f"direct scan release case lacks the exact edge size at line {line_number}")
    if type(report.get("version")) is not int or report["version"] != 1 or \
            report.get("target") != source or \
            type(report.get("root_size")) is not int or \
            report["root_size"] != identity["size"] or \
            report.get("completion") != row["completion"]:
        fail(f"direct scan report does not bind its input/outcome at line {line_number}")
    for field in (
        "logical_bytes", "matcher_bytes", "contiguous_bytes", "temporary_bytes",
        "files_scanned", "max_recursion_depth", "elapsed_ms",
        "parser_operations", "detector_operations", "skipped_operations",
    ):
        if type(report.get(field)) is not int or report[field] != int(row[field]):
            fail(f"direct scan report {field} differs from its case at line {line_number}")
    completion = row["completion"]
    status = report.get("status")
    verdict = report.get("verdict")
    if type(status) is not int or type(verdict) is not int:
        fail(f"direct scan report has invalid status/verdict at line {line_number}")
    if completion == "COMPLETE":
        valid_outcome = status == 0 and verdict in (0, 1) and \
            report.get("last_alert") in (None, "") and \
            report.get("last_alert_offset") is None and \
            report["logical_bytes"] == identity["size"] and \
            report["files_scanned"] > 0 and report["skipped_operations"] == 0
    elif completion == "DETECTION_TERMINATED":
        valid_outcome = status in (0, 1) and verdict in (2, 3) and \
            report.get("last_alert") == row["alert_signature"]
        if row["alert_offset_scope"] == "root-input":
            valid_outcome = valid_outcome and \
                row["alert_offset_source"] == "structured-report" and \
                row["alert_offset_evidence"] == report_name and \
                report.get("last_alert_offset") == int(row["alert_offset"])
        elif row["alert_offset_scope"] == "nested-member":
            valid_outcome = valid_outcome and \
                row["alert_offset_source"] == "matcher-debug-log" and \
                row["alert_offset_evidence"] == log_name and \
                report.get("last_alert_offset") is None
            escaped = re.escape(row["alert_signature"])
            if not row["alert_signature"].endswith(".UNOFFICIAL"):
                escaped += r"(?:\.UNOFFICIAL)?"
            trace = rf"(?:^|[ \t])signature {escaped} matched at {re.escape(row['alert_offset'])}(?=[ \t\r\n]|$)"
            log = log_path.read_text(encoding="utf-8", errors="replace")
            valid_outcome = valid_outcome and re.search(trace, log) is not None
        else:
            valid_outcome = False
    else:
        if completion != "LIMIT_INCOMPLETE" or \
                row["reason"] != "Heuristics.Limits.Exceeded.MaxFileSize":
            fail(f"direct scan case has an unsupported limit reason at line {line_number}")
        valid_outcome = status != 0 and \
            verdict in (0, 1) and report.get("reason") == row["reason"] and \
            report.get("last_alert") in (None, "") and \
            report.get("last_alert_offset") is None and \
            report["logical_bytes"] == 0 and report["matcher_bytes"] == 0 and \
            report["parser_operations"] == 0 and report["skipped_operations"] > 0 and \
            report.get("max_file_size") == 32 * 1024 * 1024 * 1024
    if not valid_outcome:
        fail(f"direct scan report contradicts its case at line {line_number}")
    log = log_path.read_text(encoding="utf-8", errors="replace")
    if completion != "LIMIT_INCOMPLETE" and \
            f"{source} FileHash: {row['fixture_sha256']} (sha2-256)" not in log:
        fail(f"direct scan log lacks the exact input hash at line {line_number}")
    if completion == "COMPLETE" and f"{source}: OK" not in log:
        fail(f"direct scan log lacks clean completion at line {line_number}")
    if completion == "DETECTION_TERMINATED" and \
            f"{source}: {row['alert_signature']} FOUND" not in log:
        fail(f"direct scan log lacks the exact detection at line {line_number}")
    if completion == "LIMIT_INCOMPLETE" and \
            "MaxFileSize" not in log and "max file size" not in log.lower():
        fail(f"direct scan log lacks the size-limit diagnostic at line {line_number}")


def verify_alert_offset_artifact(
    row: dict[str, str], root: Path, line_number: int,
) -> None:
    """Recheck the explicitly scoped offset source retained by a case."""
    path = safe_evidence_file(
        root, row["alert_offset_evidence"],
        f"acceptance record offset evidence at line {line_number}",
    )
    if row["alert_offset_scope"] == "root-input":
        if row["alert_offset_source"] != "structured-report":
            fail(f"root-input offset is not sourced from a structured report at line {line_number}")
        reports = [line for line in path.read_text(encoding="utf-8").splitlines()
                   if line.strip()]
        if len(reports) != 1:
            fail(f"root-input offset report is not exactly one object at line {line_number}")
        report = load_json_object(reports[0], "root-input offset report")
        if report.get("completion") != "DETECTION_TERMINATED" or \
                report.get("last_alert") != row["alert_signature"] or \
                report.get("last_alert_offset") != int(row["alert_offset"]):
            fail(f"root-input offset report contradicts its acceptance record at line {line_number}")
        return

    if row["alert_offset_scope"] != "nested-member" or \
            row["alert_offset_source"] != "matcher-debug-log":
        fail(f"acceptance record has an unsupported offset scope/source at line {line_number}")
    escaped = re.escape(row["alert_signature"])
    if not row["alert_signature"].endswith(".UNOFFICIAL"):
        escaped += r"(?:\.UNOFFICIAL)?"
    trace = rf"(?:^|[ \t])signature {escaped} matched at {re.escape(row['alert_offset'])}(?=[ \t\r\n]|$)"
    if re.search(trace, path.read_text(encoding="utf-8", errors="replace")) is None:
        fail(f"nested-member matcher log lacks the exact signature offset at line {line_number}")


def safe_evidence_file(root: Path, value: str, label: str) -> Path:
    """Resolve a retained evidence file without following a symlink path."""
    if not value or value.startswith("/"):
        fail(f"{label} has an unsafe artifact path: {value!r}")
    root = root.resolve()
    relative = Path(value)
    lexical = root / relative
    current = root
    for part in relative.parts:
        if part in ("", "."):
            continue
        if part == "..":
            current = current.parent
            continue
        current /= part
        if current.is_symlink():
            fail(f"{label} is symlinked: {value}")
    path = lexical.resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{label} escapes evidence root") from error
    if not path.is_file():
        fail(f"{label} is missing or not a regular file: {value}")
    return path


def read_tsv(path: Path, header: list[str]) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8") as stream:
            reader = csv.reader(stream, delimiter="\t", strict=True)
            actual = next(reader, None)
            if actual != header:
                fail(f"{path} has an invalid header")
            rows: list[dict[str, str]] = []
            for line_number, values in enumerate(reader, start=2):
                if len(values) != len(header):
                    fail(
                        f"{path} has {len(values)} columns at line {line_number}; "
                        f"expected {len(header)}"
                    )
                row = dict(zip(header, values))
                if any(value == "" for value in row.values()):
                    fail(f"{path} has an empty field at line {line_number}")
                rows.append(row)
    except csv.Error as error:
        fail(f"{path} has malformed TSV: {error}")
    except OSError as error:
        fail(f"cannot read {path}: {error}")
    return rows


def case_evidence_roots(
    evidence_root: Path, records: list[dict[str, str]],
) -> dict[tuple[str, str, str], Path]:
    """Route each row to a retained case directory within one evidence root.

    A missing map preserves the original single-root format. A present map
    must cover exactly the records being verified; no absolute, parent, or
    symlinked path may redirect verification to another evidence bundle.
    """
    root = evidence_root.resolve()
    manifest = root / CASE_ROOT_PATH
    keys = {(row["kind"], row["id"], row["case_id"]) for row in records}
    if manifest.is_symlink():
        fail("case evidence root map is symlinked")
    if not manifest.exists():
        return {key: root for key in keys}
    manifest = safe_evidence_file(root, CASE_ROOT_PATH, "case evidence root map")
    mapped: dict[tuple[str, str, str], Path] = {}
    for row in read_tsv(manifest, CASE_ROOT_HEADER):
        key = (row["kind"], row["id"], row["case_id"])
        if key in mapped:
            fail(f"case evidence root map duplicates a case: {':'.join(key)}")
        if key not in keys:
            fail(f"case evidence root map has an unknown case: {':'.join(key)}")
        relative = Path(row["relative_root"])
        if relative.is_absolute() or any(part in ("..", "") for part in relative.parts):
            fail(f"case evidence root map has an unsafe directory: {row['relative_root']}")
        current = root
        for part in relative.parts:
            current /= part
            if current.is_symlink():
                fail(f"case evidence root map is symlinked: {row['relative_root']}")
        case_root = current.resolve()
        if not case_root.is_dir():
            fail(f"case evidence root map directory is missing: {row['relative_root']}")
        mapped[key] = case_root
    if set(mapped) != keys:
        fail(f"case evidence root map is missing cases: {sorted(keys - set(mapped))}")
    return mapped


def validate_service_lifecycle(path: Path, label: str) -> None:
    """Validate the retained daemon health and cleanup contract."""
    rows = read_tsv(path, SERVICE_LIFECYCLE_HEADER)
    actual: dict[str, str] = {}
    for row in rows:
        event = row["event"]
        if event in actual:
            fail(f"{label} duplicates lifecycle event: {event}")
        if event not in SERVICE_LIFECYCLE_EXPECTED:
            fail(f"{label} has an unknown lifecycle event: {event}")
        actual[event] = row["result"]
    if actual != SERVICE_LIFECYCLE_EXPECTED:
        fail(f"{label} does not prove the complete daemon lifecycle contract")


def load_capabilities(path: Path) -> list[dict[str, str]]:
    rows = read_tsv(path, MANIFEST_HEADER)
    seen: set[tuple[str, str]] = set()
    for line_number, row in enumerate(rows, start=2):
        key = (row["kind"], row["id"])
        if key in seen:
            fail(f"capability map source has a duplicate capability at line {line_number}")
        seen.add(key)
    if not rows:
        fail("capability manifest is empty")
    return rows


def case_suffixes(kind: str, identifier: str) -> list[str]:
    key = (kind, identifier)
    if key in REQUIRED_UNSUPPORTED:
        return ["required-behavior", "required-failure"]
    if kind == "unsupported":
        return ["unsupported-policy"]
    if kind == "on-access" and identifier == "permission":
        return [
            "clean-edge", "detection-edge", "limit-edge", "resource-edge",
            "timeout-edge", "parser-edge",
        ]
    if kind in INGRESS_KINDS or (kind == "library" and identifier in {"path", "fd", "fmap"}):
        return ["clean-edge", "detection-edge", "limit-edge"]
    if kind == "parser":
        return ["valid-complete", "late-detection", "malformed-confirmed", "limit"]
    if kind == "matcher":
        return ["exact-tail", "limit", "fault"]
    if kind == "feature":
        return ["enabled", "disabled-or-rejection"]
    return ["complete", "late-detection", "fault"]


def expected_map(capabilities: list[dict[str, str]]) -> list[dict[str, str]]:
    result = []
    for row in capabilities:
        kind = row["kind"]
        identifier = row["id"]
        case_ids = [f"{kind}:{identifier}:{suffix}" for suffix in case_suffixes(kind, identifier)]
        result.append({"kind": kind, "id": identifier, "required_case_ids": ",".join(case_ids)})
    return result


def validate_map(manifest: Path, mapping: Path) -> list[dict[str, str]]:
    expected = expected_map(load_capabilities(manifest))
    actual = read_tsv(mapping, MAP_HEADER)
    seen: set[tuple[str, str]] = set()
    for line_number, row in enumerate(actual, start=2):
        key = (row["kind"], row["id"])
        if key in seen:
            fail(f"acceptance map duplicates {key[0]}:{key[1]} at line {line_number}")
        seen.add(key)
        cases = row["required_case_ids"].split(",")
        if not cases or any(not CASE_ID_RE.fullmatch(case_id) for case_id in cases):
            fail(f"acceptance map has invalid case IDs at line {line_number}")
        if len(cases) != len(set(cases)):
            fail(f"acceptance map repeats a case ID at line {line_number}")
    if actual != expected:
        expected_keys = {(row["kind"], row["id"]) for row in expected}
        actual_keys = {(row["kind"], row["id"]) for row in actual}
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        if missing:
            fail(f"acceptance map is missing capabilities: {missing[:5]}")
        if extra:
            fail(f"acceptance map has unknown capabilities: {extra[:5]}")
        fail("acceptance map case requirements do not match the reviewed routing rules")
    return actual


def validate_records(
    records_path: Path,
    mapping: list[dict[str, str]],
    required_capability: tuple[str, str] | None = None,
    evidence_root: Path | None = None,
    required_capabilities: tuple[tuple[str, str], ...] = (),
    expected_source_sha256: str | None = None,
) -> int:
    if expected_source_sha256 is not None and not HASH_RE.fullmatch(expected_source_sha256):
        fail("acceptance records have an invalid expected source manifest SHA-256")
    rows = read_tsv(records_path, RECORD_HEADER)
    roots = case_evidence_roots(evidence_root, rows) if evidence_root is not None else {}
    required = {
        (row["kind"], row["id"]): set(row["required_case_ids"].split(","))
        for row in mapping
    }
    seen: set[tuple[str, str, str]] = set()
    verified_service_roles: dict[tuple[Path, str], str] = {}
    completions = {
        "COMPLETE": ("0", {"CLEAN", "TRUSTED"}),
        "DETECTION_TERMINATED": ("1", {"DETECTED", "MALWARE"}),
        "LIMIT_INCOMPLETE": ("2", {"INCOMPLETE"}),
        "UNSUPPORTED": ("2", {"INCOMPLETE"}),
        "MALFORMED_CONFIRMED": ("2", {"INCOMPLETE"}),
        "RESOURCE_FAILURE": ("2", {"INCOMPLETE"}),
        "APPLICATION_ABORT": ("2", {"INCOMPLETE"}),
    }
    numeric_fields = (
        "exit_code", "logical_bytes", "matcher_bytes", "contiguous_bytes",
        "temporary_bytes", "files_scanned", "max_recursion_depth", "elapsed_ms",
        "parser_operations", "detector_operations", "skipped_operations",
    )
    for line_number, row in enumerate(rows, start=2):
        key = (row["kind"], row["id"])
        case_key = (row["kind"], row["id"], row["case_id"])
        if key not in required:
            fail(f"acceptance record names an unmapped capability at line {line_number}")
        if row["case_id"] not in required[key]:
            fail(f"acceptance record names an unrequired case at line {line_number}")
        if case_key in seen:
            fail(f"acceptance records duplicate a capability case at line {line_number}")
        seen.add(case_key)
        for field in ("source_manifest_sha256", "build_identity_sha256", "config_sha256",
                      "fixture_sha256", "oracle_sha256", "database_sha256"):
            if not HASH_RE.fullmatch(row[field]):
                fail(f"acceptance record has an invalid {field} at line {line_number}")
        if expected_source_sha256 is not None and \
                row["source_manifest_sha256"] != expected_source_sha256:
            fail(f"acceptance record source does not match the final candidate at line {line_number}")
        for field in numeric_fields:
            if not NONNEGATIVE_RE.fullmatch(row[field]):
                fail(f"acceptance record has an invalid {field} at line {line_number}")
        if row["exit_code"] not in {"0", "1", "2"}:
            fail(f"acceptance record has an invalid exit code at line {line_number}")
        completion = row["completion"]
        if completion not in completions:
            fail(f"acceptance record has an invalid completion at line {line_number}")
        allowed_completions = case_completion_contract(row["case_id"])
        if allowed_completions is None:
            fail(
                f"acceptance record has no completion contract at line {line_number}: "
                f"{row['case_id']}"
            )
        if completion not in allowed_completions:
            fail(
                f"acceptance record completion does not match its case contract "
                f"at line {line_number}: {row['case_id']} requires "
                f"{sorted(allowed_completions)}"
            )
        expected_exit, verdicts = completions[completion]
        if row["exit_code"] != expected_exit or row["verdict"] not in verdicts:
            fail(f"acceptance record has contradictory outcome fields at line {line_number}")
        if completion == "DETECTION_TERMINATED":
            if row["alert_signature"] == "-" or not NONNEGATIVE_RE.fullmatch(row["alert_offset"]):
                fail(f"detection case lacks an exact alert binding at line {line_number}")
            if (row["alert_offset_scope"], row["alert_offset_source"]) not in {
                ("root-input", "structured-report"),
                ("nested-member", "matcher-debug-log"),
            } or row["alert_offset_evidence"] in {"", "-"}:
                fail(f"detection case lacks explicit offset scope/source evidence at line {line_number}")
        elif row["alert_signature"] != "-" or row["alert_offset"] != "-":
            fail(f"non-detection case carries an alert binding at line {line_number}")
        elif (row["alert_offset_scope"], row["alert_offset_source"],
              row["alert_offset_evidence"]) != ("none", "none", "-"):
            fail(f"non-detection case carries offset scope/source evidence at line {line_number}")
        if row["skipped_operations"] != "0" and completion == "COMPLETE":
            fail(f"complete case has skipped operations at line {line_number}")
        if row["sanitizer"] not in {
            "development", "release", "c-asan-ubsan", "rust-asan",
            "release+c-asan-ubsan+rust-asan",
        }:
            fail(f"acceptance record has invalid sanitizer identity at line {line_number}")
        if row["health"] != "pass" or row["cleanup"] != "pass" or row["artifacts"] in {"", "-"}:
            fail(f"acceptance record lacks health/cleanup/artifact evidence at line {line_number}")
        if not row["platform"] or not row["fixture_role"] or not row["resource_phase"] or not row["reason"]:
            fail(f"acceptance record lacks required contextual evidence at line {line_number}")
        if row["fixture_role"] == "-":
            fail(f"acceptance record lacks a fixture role at line {line_number}")
        resource_phases = parse_resource_phases(row["resource_phase"], line_number)
        has_release_budget = {"rss", "temporary"}.issubset(resource_phases)
        has_development_budget = {"max-file", "max-temp"}.issubset(resource_phases)
        if not (has_release_budget or has_development_budget):
            fail(
                f"acceptance record lacks structured resource phases "
                f"at line {line_number}"
            )
        if (row["kind"], row["id"]) == ("matcher", "pcre") and \
                not {"pcre", "post-pcre"}.issubset(resource_phases):
            fail(f"acceptance record lacks PCRE resource phases at line {line_number}")
        if evidence_root is not None:
            root = roots[case_key]
            artifact_paths: list[Path] = []
            artifact_names = row["artifacts"].split(",")
            for artifact in artifact_names:
                path = safe_evidence_file(
                    root, artifact, f"acceptance record artifact at line {line_number}"
                )
                artifact_paths.append(path)
            if completion == "DETECTION_TERMINATED" and \
                    row["alert_offset_evidence"] not in artifact_names:
                fail(f"acceptance record offset evidence is not a retained artifact at line {line_number}")
            if completion == "DETECTION_TERMINATED":
                verify_alert_offset_artifact(row, root, line_number)
            lifecycle_names = [
                artifact for artifact in row["artifacts"].split(",")
                if artifact.startswith("provenance/service-lifecycle-")
            ]
            lifecycle_bound = SERVICE_LIFECYCLE_MARKER in row["resource_phase"]
            if lifecycle_names and not lifecycle_bound:
                fail(
                    f"acceptance record lifecycle artifact is missing its binding marker "
                    f"at line {line_number}"
                )
            if lifecycle_bound:
                if len(lifecycle_names) != 1:
                    fail(
                        f"acceptance record must bind exactly one lifecycle artifact "
                        f"at line {line_number}"
                    )
                lifecycle_path = artifact_paths[row["artifacts"].split(",").index(lifecycle_names[0])]
                validate_service_lifecycle(
                    lifecycle_path,
                    f"acceptance record lifecycle artifact at line {line_number}",
                )
            artifact_hashes = {sha256(path) for path in artifact_paths}
            for field in (
                "source_manifest_sha256", "build_identity_sha256", "config_sha256",
                "oracle_sha256", "database_sha256",
            ):
                if row[field] not in artifact_hashes:
                    fail(
                        f"acceptance record {field} does not match a retained artifact "
                        f"at line {line_number}"
                    )
            inputs_path = root / "provenance/service-inputs-before.json"
            after_inputs_path = root / "provenance/service-inputs-after.json"
            direct_inputs_path = root / "provenance/direct-inputs-before.json"
            direct_after_path = root / "provenance/direct-inputs-after.json"
            direct_present = (
                direct_inputs_path.exists() or direct_inputs_path.is_symlink() or
                direct_after_path.exists() or direct_after_path.is_symlink()
            )
            fixture_bound = False
            if (inputs_path.exists() or after_inputs_path.exists()) and \
                    direct_present:
                fail(f"acceptance record has ambiguous service/direct input evidence at line {line_number}")
            if lifecycle_bound and not inputs_path.is_file():
                fail(
                    f"lifecycle-bound acceptance record lacks service input identity evidence "
                    f"at line {line_number}"
                )
            if inputs_path.is_file() and row["fixture_role"] != "-":
                if inputs_path not in artifact_paths:
                    fail(
                        f"acceptance record does not retain service input identity evidence "
                        f"at line {line_number}"
                    )
                if after_inputs_path not in artifact_paths:
                    fail(
                        f"acceptance record does not retain service input after evidence "
                        f"at line {line_number}"
                    )
                try:
                    service_inputs = load_json(
                        inputs_path.read_text(encoding="utf-8"),
                        "service input identity evidence",
                    )
                except OSError as error:
                    raise ValueError("service input identity evidence is malformed") from error
                if not isinstance(service_inputs, dict) or \
                        type(service_inputs.get("version")) is not int or \
                        service_inputs.get("version") != 1 or \
                        not isinstance(service_inputs.get("inputs"), dict):
                    fail("service input identity evidence is malformed")
                if inputs_path.read_bytes() != after_inputs_path.read_bytes():
                    fail(
                        f"service input allocation/content evidence changed during qualification "
                        f"at line {line_number}"
                    )
                inputs = service_inputs["inputs"]
                identity = inputs.get(row["fixture_role"])
                if not isinstance(identity, dict) or identity.get("sha256") != row["fixture_sha256"]:
                    fail(
                        f"acceptance record fixture hash does not match service input evidence "
                        f"at line {line_number}"
                    )
                role = row["fixture_role"]
                scoped_role = (root, role)
                if scoped_role not in verified_service_roles:
                    verify_service_fixture(identity, row["fixture_sha256"], role)
                    verified_service_roles[scoped_role] = row["fixture_sha256"]
                elif verified_service_roles[scoped_role] != row["fixture_sha256"]:
                    fail(f"service input fixture role has conflicting hashes at line {line_number}")
                fixture_bound = True
            if direct_present:
                if key != ("clamscan", "file"):
                    fail(f"direct input identity is only valid for clamscan:file at line {line_number}")
                if not direct_inputs_path.is_file() or not direct_after_path.is_file():
                    fail(f"direct input identity requires before and after evidence at line {line_number}")
                if direct_inputs_path not in artifact_paths or direct_after_path not in artifact_paths:
                    fail(f"direct input identity is not retained by the case at line {line_number}")
                if direct_inputs_path.read_bytes() != direct_after_path.read_bytes():
                    fail(f"direct input identity changed during qualification at line {line_number}")
                direct_inputs = load_json_object(
                    direct_inputs_path.read_text(encoding="utf-8"),
                    "direct input identity evidence",
                )
                identities = direct_inputs.get("inputs")
                role = row["fixture_role"]
                if type(direct_inputs.get("version")) is not int or \
                        direct_inputs["version"] != 1 or \
                        not isinstance(identities, dict) or set(identities) != {role}:
                    fail(f"direct input identity evidence is malformed at line {line_number}")
                identity = identities[role]
                if not isinstance(identity, dict) or \
                        identity.get("sha256") != row["fixture_sha256"] or \
                        not isinstance(identity.get("input"), str) or \
                        type(identity.get("size")) is not int:
                    fail(f"direct input identity does not match its case at line {line_number}")
                verify_direct_scan_artifacts(row, identity, set(artifact_names), root, line_number)
                verify_service_fixture(
                    identity, row["fixture_sha256"], role, label="direct input",
                )
                fixture_bound = True
            if not fixture_bound and row["fixture_sha256"] not in artifact_hashes:
                # Runtime/parser evidence may not have service-input JSON, but
                # it still must retain the exact fixture or an equivalent
                # immutable fixture artifact. A bare 64-hex label is not a
                # binding to the input that was actually scanned.
                fail(
                    f"acceptance record fixture hash is not bound to a retained fixture artifact "
                    f"at line {line_number}"
                )
    requested_capabilities = list(required_capabilities)
    if required_capability is not None:
        requested_capabilities.append(required_capability)
    for requested in requested_capabilities:
        if requested not in required:
            fail(
                f"requested capability is not present in the case map: "
                f"{requested[0]}:{requested[1]}"
            )
        present = {case_id for kind, identifier, case_id in seen
                   if (kind, identifier) == requested}
        missing = sorted(required[requested] - present)
        if missing:
            fail(
                f"acceptance records are missing required cases for "
                f"{requested[0]}:{requested[1]}: {missing}"
            )
    return len(rows)


def write_map(manifest: Path, destination: Path) -> None:
    rows = expected_map(load_capabilities(manifest))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=MAP_HEADER, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("docs/largefile-capabilities.tsv"))
    parser.add_argument("--map", type=Path, default=Path("docs/largefile-capability-case-map.tsv"))
    parser.add_argument("--records", type=Path, default=Path("docs/largefile-acceptance-cases.tsv"))
    parser.add_argument("--write-map", action="store_true")
    parser.add_argument("--check-map", action="store_true")
    parser.add_argument("--check-records", action="store_true")
    parser.add_argument(
        "--evidence-root", type=Path,
        help="recompute retained artifact and service-fixture identities",
    )
    parser.add_argument(
        "--require-capability", nargs=2, action="append", metavar=("KIND", "ID"),
        help="require all mapped cases for a capability; may be repeated",
    )
    parser.add_argument(
        "--require-r09", action="store_true",
        help="require all focused R09 behavior/failure case pairs",
    )
    parser.add_argument(
        "--expected-source-sha256",
        help="require every case to use the source manifest selected by the release gate",
    )
    args = parser.parse_args(argv)
    try:
        if args.write_map:
            write_map(args.manifest, args.map)
        mapping = validate_map(args.manifest, args.map) if args.check_map or args.check_records else []
        required_capabilities = tuple(tuple(item) for item in (args.require_capability or []))
        if args.require_r09:
            required_capabilities += R09_REQUIRED_CAPABILITIES
        if (required_capabilities or args.require_r09) and not args.check_records:
            parser.error("--require-capability/--require-r09 requires --check-records")
        record_count = (
            validate_records(
                args.records, mapping,
                evidence_root=args.evidence_root,
                required_capabilities=required_capabilities,
                expected_source_sha256=args.expected_source_sha256,
            )
            if args.check_records else None
        )
        if args.check_map:
            print(f"large-file acceptance case map passed ({len(mapping)} capabilities)")
        if args.check_records:
            print(f"large-file acceptance record schema passed ({record_count} records)")
        if not args.write_map and not args.check_map and not args.check_records:
            parser.error("one of --write-map, --check-map, or --check-records is required")
    except (OSError, ValueError, csv.Error) as error:
        print(f"large-file acceptance cases failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
