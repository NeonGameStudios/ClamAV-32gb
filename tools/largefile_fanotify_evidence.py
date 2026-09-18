#!/usr/bin/env python3
"""Validate retained Linux fanotify permission evidence.

This verifier checks the evidence contract only.  It never creates a mount,
starts clamonacc, or fabricates kernel events.  A real R13 run must provide
the JSON document and the retained event/scan artifacts that it names.

The scan-report artifact is a one-record, case-bound structured report copied
from the on-access clamd exchange by the runner.  It is not a free-form log;
the process log remains a separate artifact when a case needs text evidence.
Prevention reports must retain the same ``clamonacc_event_id`` as the selected
permission event; monitoring-only reports must retain zero because they have
no permission-event join.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import re
import struct
import sys

import largefile_acceptance_cases as acceptance_cases

HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
HEX_RE = re.compile(r"[0-9a-f]*\Z")
FAN_OPEN_PERM_MASK = 0x00010000
CASE_CONTRACT = {
    "clean": ("COMPLETE", 0, "allow", "FAN_ALLOW"),
    "detection": ("DETECTION_TERMINATED", 1, "deny", "FAN_DENY"),
    "limit": ("LIMIT_INCOMPLETE", 2, "deny", "FAN_DENY"),
    "resource": ("RESOURCE_FAILURE", 2, "deny", "FAN_DENY"),
    "timeout": ("APPLICATION_ABORT", 2, "deny", "FAN_DENY"),
    "parser": ("MALFORMED_CONFIRMED", 2, "deny", "FAN_DENY"),
}
MONITORING_CASES = tuple(CASE_CONTRACT)
IDENTITY_FIELDS = ("source_manifest", "build_identity", "config")
SCAN_REPORT_FIELDS = (
    "status", "verdict", "root_size", "logical_bytes", "matcher_bytes",
    "contiguous_bytes", "temporary_bytes", "files_scanned",
    "max_recursion_depth", "elapsed_ms", "parser_operations",
    "detector_operations", "skipped_operations",
)


def fail(message: str) -> None:
    raise ValueError(message)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def relative_file(root: Path, value: object, label: str) -> Path:
    require(isinstance(value, str) and value not in {"", "-"},
            f"{label} is missing")
    require(not value.startswith("/"), f"{label} must be relative")
    relative = PurePosixPath(value)
    require(not relative.is_absolute() and ".." not in relative.parts,
            f"{label} is unsafe")
    candidate = root / relative.as_posix()
    require(candidate.is_file() and not candidate.is_symlink(),
            f"{label} is missing or symlinked")
    path = candidate.resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"{label} escapes the evidence root") from error
    return path


def validate_identity(root: Path, identity: object, expected_source: str) -> None:
    require(isinstance(identity, dict), "fanotify identity evidence is invalid")
    for field in IDENTITY_FIELDS:
        record = identity.get(field)
        require(isinstance(record, dict), f"fanotify identity lacks {field}")
        path = relative_file(root, record.get("path"), f"fanotify {field} path")
        expected = record.get("sha256")
        require(isinstance(expected, str) and HASH_RE.fullmatch(expected),
                f"fanotify {field} hash is invalid")
        require(digest(path) == expected,
                f"fanotify {field} hash does not verify")
        if field == "source_manifest":
            require(expected == expected_source,
                    "fanotify source manifest hash is not the proof binding")


def validate_artifacts(root: Path, artifacts: object, label: str,
                       required_roles: set[str]) -> None:
    require(isinstance(artifacts, list) and artifacts,
            f"{label} has no retained artifacts")
    seen_paths: set[str] = set()
    seen_roles: set[str] = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict), f"{label} has an invalid artifact")
        path_text = artifact.get("path")
        require(isinstance(path_text, str) and path_text not in seen_paths,
                f"{label} has a duplicate or invalid artifact")
        seen_paths.add(path_text)
        path = relative_file(root, path_text, f"{label} artifact")
        role = artifact.get("role")
        require(isinstance(role, str) and role not in seen_roles,
                f"{label} has a duplicate or invalid artifact role")
        seen_roles.add(role)
        expected = artifact.get("sha256")
        require(isinstance(expected, str) and HASH_RE.fullmatch(expected),
                f"{label} artifact hash is invalid")
        require(digest(path) == expected,
                f"{label} artifact hash does not verify")
    require(required_roles <= seen_roles,
            f"{label} lacks required retained artifacts: "
            f"{sorted(required_roles - seen_roles)}")


def artifact_path(root: Path, artifacts: object, label: str, role: str) -> Path:
    require(isinstance(artifacts, list), f"{label} artifacts are not a list")
    for artifact in artifacts:
        if isinstance(artifact, dict) and artifact.get("role") == role:
            return relative_file(
                root, artifact.get("path"), f"{label} {role} artifact"
            )
    fail(f"{label} lacks retained {role} artifact")


def load_json_lines(path: Path, label: str) -> list[dict]:
    rows = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line:
            continue
        rows.append(acceptance_cases.load_json_object(
            line, f"{label} line {line_number}"
        ))
    require(rows, f"{label} is empty")
    return rows


def validate_kernel_event_artifact(
    path: Path, label: str, event_id: int, fixture_hash: str,
    expected_response: str,
) -> None:
    records = load_json_lines(path, label)
    seen_ids: set[int] = set()
    matching = []
    target_count = 0
    for record in records:
        require(record.get("event_kind") == "FAN_OPEN_PERM",
                f"{label} has a non-permission event")
        record_id = record.get("event_id")
        require(type(record_id) is int and record_id >= 1 and record_id not in seen_ids,
                f"{label} has an invalid or duplicate event ID")
        seen_ids.add(record_id)
        require(record.get("fixture_sha256") == fixture_hash,
                f"{label} is not bound to the case fixture")
        require(type(record.get("target")) is bool,
                f"{label} has no boolean target marker")
        if record.get("target") is True:
            target_count += 1
        mask = record.get("mask")
        require(type(mask) is int and mask & FAN_OPEN_PERM_MASK,
                f"{label} does not retain FAN_OPEN_PERM mask evidence")
        names = record.get("mask_names")
        require(isinstance(names, list) and "FAN_OPEN_PERM" in names,
                f"{label} does not retain FAN_OPEN_PERM name evidence")
        require(record.get("observer_response") == "FAN_ALLOW",
                f"{label} lacks the recorder's explicit observer response")
        require(record.get("permission_response") == expected_response,
                f"{label} lacks ClamAV's explicit permission response")
        event_path = record.get("path")
        require(isinstance(event_path, str) and event_path.startswith("/"),
                f"{label} has no resolved absolute event path")
        for field in (
            "timestamp_ns", "event_fd", "event_pid", "event_len",
            "metadata_len", "metadata_version",
        ):
            value = record.get(field)
            require(type(value) is int and value >= 0,
                    f"{label} has invalid {field}")
        raw = record.get("raw_metadata_hex")
        require(isinstance(raw, str) and len(raw) % 2 == 0 and HEX_RE.fullmatch(raw),
                f"{label} has invalid raw metadata")
        try:
            raw_bytes = bytes.fromhex(raw)
            raw_event_len, raw_version, _reserved, raw_metadata_len, raw_mask, raw_fd, raw_pid = struct.unpack(
                "<IBBH Qii", raw_bytes[:24]
            )
        except (ValueError, struct.error) as error:
            raise ValueError(f"{label} raw metadata cannot be decoded") from error
        require(len(raw_bytes) >= 24 and raw_metadata_len == len(raw_bytes) and
                raw_event_len >= raw_metadata_len and
                raw_version == record["metadata_version"] and
                raw_event_len == record["event_len"] and
                raw_mask == record["mask"] and
                raw_fd == record["event_fd"] and
                raw_pid == record["event_pid"],
                f"{label} raw metadata does not match structured event fields")
        if record_id == event_id:
            require(record.get("target") is True,
                    f"{label} selected event is not target-bound")
            matching.append(record)
    require(target_count == 1,
            f"{label} does not contain exactly one target-bound event")
    require(len(matching) == 1,
            f"{label} does not contain exactly one selected event ID")


def validate_actor_artifact(
    path: Path, label: str, case_name: str, event_id: int,
    fixture_hash: str, expected_action: str,
) -> None:
    records = load_json_lines(path, label)
    require(len(records) == 1, f"{label} must contain one actor result")
    record = records[0]
    require(record.get("case_name") == case_name,
            f"{label} is not bound to case {case_name}")
    require(record.get("fixture_sha256") == fixture_hash,
            f"{label} is not bound to the case fixture")
    require(record.get("event_id") == event_id,
            f"{label} is not bound to the selected kernel event")
    opened = record.get("opened")
    require(type(opened) is bool,
            f"{label} has no boolean open observation")
    require(record.get("observed_action") == expected_action and
            opened is (expected_action == "allow"),
            f"{label} contradicts the observed permission action")
    actor_uid = record.get("actor_uid")
    require(type(actor_uid) is int and actor_uid > 0,
            f"{label} has an invalid non-root actor UID")
    exit_code = record.get("actor_exit_code")
    require(type(exit_code) is int and (exit_code == 0) is opened,
            f"{label} actor exit code contradicts the open observation")
    require(isinstance(record.get("stderr"), str),
            f"{label} has no actor stderr capture")


def validate_scan_report_artifact(
    path: Path, label: str, case_name: str, fixture_hash: str,
    expected_completion: str, expected_exit_code: int, expected_event_id: int,
) -> None:
    """Require a real, case-bound structured report rather than text filler."""
    records = load_json_lines(path, label)
    require(len(records) == 1, f"{label} must contain one structured report")
    report = records[0]
    require(report.get("version") == 1 and
            report.get("evidence_type") == "on-access-scan",
            f"{label} has an invalid structured report schema")
    require(report.get("case_name") == case_name,
            f"{label} is not bound to case {case_name}")
    require(report.get("fixture_sha256") == fixture_hash,
            f"{label} is not bound to the case fixture")
    report_event_id = report.get("clamonacc_event_id")
    require(type(report_event_id) is int and report_event_id == expected_event_id,
            f"{label} is not bound to clamonacc event {expected_event_id}")
    require(report.get("completion") == expected_completion,
            f"{label} completion does not match the case contract")
    require(type(report.get("scan_exit_code")) is int and
            report["scan_exit_code"] == expected_exit_code,
            f"{label} scan exit does not match the case contract")
    for field in SCAN_REPORT_FIELDS:
        value = report.get(field)
        require(type(value) is int and value >= 0,
                f"{label} field {field} is not a non-negative integer")
    require(report["root_size"] > 0,
            f"{label} does not retain a positive scanned root size")
    if expected_completion == "COMPLETE":
        require(report["status"] == 0 and report["verdict"] in (0, 1) and
                report["skipped_operations"] == 0,
                f"{label} complete report is not clean and successful")
        require(report.get("last_alert") in (None, "") and
                report.get("last_alert_offset") is None,
                f"{label} clean report contains an unexpected alert")
    elif case_name == "detection":
        require(report["verdict"] in (2, 3),
                f"{label} detection report is not non-clean")
        require(isinstance(report.get("last_alert"), str) and
                report["last_alert"],
                f"{label} detection report lacks an exact alert")
        require(type(report.get("last_alert_offset")) is int and
                report["last_alert_offset"] >= 0,
                f"{label} detection report lacks an alert offset")
    else:
        require(report["status"] != 0,
                f"{label} failure report has a clean status")
        require(isinstance(report.get("reason"), str) and
                report["reason"],
                f"{label} failure report lacks a reason")


def validate_prevention_cases(root: Path, cases: object) -> None:
    require(isinstance(cases, list), "fanotify prevention cases are not a list")
    expected_names = set(CASE_CONTRACT)
    seen: set[str] = set()
    event_ids: set[int] = set()
    for case in cases:
        require(isinstance(case, dict), "fanotify prevention case is not an object")
        name = case.get("name")
        require(isinstance(name, str) and name in expected_names,
                "fanotify prevention case has an unknown name")
        require(name not in seen, f"fanotify prevention cases duplicate {name}")
        seen.add(name)
        completion, exit_code, decision, response = CASE_CONTRACT[name]
        require(case.get("case_id") == f"on-access:permission:{name}-edge",
                f"fanotify prevention case has the wrong case ID: {name}")
        fixture_hash = case.get("fixture_sha256")
        require(isinstance(fixture_hash, str) and HASH_RE.fullmatch(fixture_hash),
                f"fanotify prevention fixture hash is invalid: {name}")
        require(case.get("kernel_event") == "FAN_OPEN_PERM",
                f"fanotify prevention case lacks a permission event: {name}")
        require(case.get("scan_completion") == completion and
                case.get("scan_exit_code") == exit_code,
                f"fanotify prevention scan outcome is wrong: {name}")
        require(case.get("permission_decision") == decision and
                case.get("kernel_response") == response and
                case.get("observed_action") == decision,
                f"fanotify prevention decision is wrong: {name}")
        require(case.get("health") == "pass" and case.get("cleanup") == "pass",
                f"fanotify prevention case lacks health/cleanup proof: {name}")
        event_id = case.get("event_id")
        require(type(event_id) is int and event_id >= 1,
                f"fanotify prevention event ID is invalid: {name}")
        require(event_id not in event_ids,
                f"fanotify prevention event ID is duplicated: {name}")
        event_ids.add(event_id)
        validate_artifacts(
            root, case.get("artifacts"), f"fanotify prevention case {name}",
            {"kernel-event", "actor-result", "scan-report"},
        )
        kernel_path = artifact_path(
            root, case.get("artifacts"), f"fanotify prevention case {name}",
            "kernel-event",
        )
        actor_path = artifact_path(
            root, case.get("artifacts"), f"fanotify prevention case {name}",
            "actor-result",
        )
        validate_kernel_event_artifact(
            kernel_path, f"fanotify prevention case {name} kernel event",
            event_id, fixture_hash, response,
        )
        validate_actor_artifact(
            actor_path, f"fanotify prevention case {name} actor result",
            name, event_id, fixture_hash, decision,
        )
        scan_path = artifact_path(
            root, case.get("artifacts"), f"fanotify prevention case {name}",
            "scan-report",
        )
        validate_scan_report_artifact(
            scan_path, f"fanotify prevention case {name} scan report",
            name, fixture_hash, completion, exit_code, event_id,
        )
    require(seen == expected_names,
            "fanotify prevention cases do not cover clean, detection, limit, "
            "resource, timeout, and parser outcomes")


def validate_monitoring_cases(root: Path, monitoring: object) -> None:
    require(isinstance(monitoring, dict), "fanotify monitoring-only evidence is invalid")
    require(monitoring.get("verified") is True,
            "fanotify monitoring-only behavior was not verified")
    require(monitoring.get("permission_events") is False,
            "monitoring-only evidence claims permission events")
    cases = monitoring.get("cases")
    require(isinstance(cases, list), "fanotify monitoring-only cases are not a list")
    seen: set[str] = set()
    for case in cases:
        require(isinstance(case, dict), "fanotify monitoring-only case is not an object")
        name = case.get("name")
        require(isinstance(name, str) and name in CASE_CONTRACT and name not in seen,
                "fanotify monitoring-only case has an unknown or duplicate name")
        seen.add(name)
        completion, exit_code, _, _ = CASE_CONTRACT[name]
        fixture_hash = case.get("fixture_sha256")
        require(isinstance(fixture_hash, str) and HASH_RE.fullmatch(fixture_hash),
                f"fanotify monitoring fixture hash is invalid: {name}")
        require(case.get("scan_completion") == completion and
                case.get("scan_exit_code") == exit_code,
                f"fanotify monitoring-only scan outcome is wrong: {name}")
        require(case.get("permission_decision") == "not-applicable" and
                case.get("kernel_response") == "FAN_NO_PERMISSION" and
                case.get("observed_action") == "allow",
                f"fanotify monitoring-only action is wrong: {name}")
        require(case.get("health") == "pass" and case.get("cleanup") == "pass",
                f"fanotify monitoring-only case lacks health/cleanup proof: {name}")
        validate_artifacts(
            root, case.get("artifacts"), f"fanotify monitoring-only case {name}",
            {"process-log", "scan-report"},
        )
        scan_path = artifact_path(
            root, case.get("artifacts"), f"fanotify monitoring-only case {name}",
            "scan-report",
        )
        # Keep the monitoring-only scan-report contract visible to the source
        # guard as well as to the runtime verifier.
        require(scan_path.is_file(), "fanotify monitoring-only scan report is missing")
        validate_scan_report_artifact(
            scan_path, f"fanotify monitoring-only case {name} scan report",
            name, fixture_hash, completion, exit_code, 0,
        )
    require(seen == set(MONITORING_CASES),
            "fanotify monitoring-only cases do not cover the complete matrix")


def validate_cleanup(cleanup: object) -> None:
    require(isinstance(cleanup, dict), "fanotify recovery/cleanup evidence is invalid")
    required = (
        "monitor_stopped", "fanotify_fd_closed", "mount_unmounted",
        "fixtures_removed", "temporary_paths_removed", "daemon_healthy",
    )
    for field in required:
        require(cleanup.get(field) is True,
                f"fanotify recovery/cleanup is incomplete: {field}")


def validate(proof_path: Path, evidence_root: Path | None = None) -> dict:
    proof_candidate = Path(proof_path)
    root = (evidence_root or proof_candidate.parent.parent).resolve()
    require(proof_candidate.is_file() and not proof_candidate.is_symlink(),
            "fanotify evidence proof is missing or symlinked")
    proof_path = proof_candidate.resolve()
    document = acceptance_cases.load_json(
        proof_path.read_text(encoding="utf-8"), "fanotify evidence proof"
    )
    require(isinstance(document, dict), "fanotify evidence proof is not an object")
    require(document.get("proof_format_version") == 1 and document.get("evidence_type") == "fanotify",
            "fanotify evidence proof format is invalid")
    require(document.get("qualification_result") == "pass",
            "fanotify evidence proof is not a passing result")
    require(document.get("capability_kind") == "on-access" and
            document.get("capability_id") == "permission",
            "fanotify evidence proof is not bound to on-access:permission")
    source_hash = document.get("source_manifest_sha256")
    require(isinstance(source_hash, str) and HASH_RE.fullmatch(source_hash),
            "fanotify source manifest proof hash is invalid")
    platform = document.get("platform")
    require(isinstance(platform, str) and platform.startswith("Linux-"),
            "fanotify evidence platform is not Linux")
    mount = document.get("mount")
    require(isinstance(mount, dict) and isinstance(mount.get("path"), str) and
            mount["path"].startswith("/") and mount.get("private") is True and
            mount.get("mounted") is True and
            isinstance(mount.get("filesystem"), str) and mount["filesystem"] and
            mount.get("permission_events") is True and
            mount.get("monitoring_only") is False,
            "fanotify evidence does not prove a private permission-event mount")
    validate_identity(root, document.get("identity"), source_hash)
    validate_prevention_cases(root, document.get("prevention_cases"))
    validate_monitoring_cases(root, document.get("monitoring_only"))
    validate_cleanup(document.get("recovery_cleanup"))
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("proof", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    args = parser.parse_args(argv)
    try:
        validate(args.proof, args.evidence_root)
    except (OSError, ValueError, TypeError) as error:
        print(f"large-file fanotify evidence failed: {error}", file=sys.stderr)
        return 1
    print("large-file fanotify permission evidence passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
