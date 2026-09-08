#!/usr/bin/env python3
"""Validate retained Linux fanotify permission evidence.

This verifier checks the evidence contract only.  It never creates a mount,
starts clamonacc, or fabricates kernel events.  A real R13 run must provide
the JSON document and the retained event/scan artifacts that it names.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys


HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
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
        require(type(event_id) is int and event_id >= 0,
                f"fanotify prevention event ID is invalid: {name}")
        require(event_id not in event_ids,
                f"fanotify prevention event ID is duplicated: {name}")
        event_ids.add(event_id)
        validate_artifacts(
            root, case.get("artifacts"), f"fanotify prevention case {name}",
            {"kernel-event", "scan-report"},
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
    try:
        document = json.loads(proof_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("fanotify evidence proof is not valid JSON") from error
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
