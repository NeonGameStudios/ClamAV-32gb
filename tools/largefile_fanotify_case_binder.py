#!/usr/bin/env python3
"""Bind real fanotify and clamonacc artifacts for one R13 case.

This utility joins artifacts retained by separate real processes.  It never
creates a kernel event, permission response, actor result, or scan outcome.  A
case is emitted only when the observer event and ClamAV permission record have
an unambiguous path/PID/metadata match, the actor is bound to the observer
event, and the raw clamonacc report carries the same ``clamonacc_event_id`` as
the permission record.  The resulting kernel and scan artifacts are shaped
for ``largefile_fanotify_evidence.py``; the caller still supplies the final
proof envelope and independent source/build/config identities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

import largefile_acceptance_cases as acceptance_cases
import largefile_fanotify_evidence as evidence


HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
PERMISSION_ARTIFACT_KIND = "clamonacc-permission-decision"
PERMISSION_EVENT_KIND = "FAN_OPEN_PERM"


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def require_digest(value: object) -> str:
    require(isinstance(value, str) and HASH_RE.fullmatch(value) is not None,
            "fixture SHA-256 must be 64 lowercase hexadecimal characters")
    return value


def require_input(path: Path, label: str) -> Path:
    require(not path.is_symlink() and path.is_file(),
            f"{label} is missing or symlinked: {path}")
    return path.resolve()


def load_json_lines(path: Path, label: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        rows.append(acceptance_cases.load_json_object(
            line, f"{label} line {line_number}"
        ))
    require(rows, f"{label} is empty")
    return rows


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def atomic_write(path: Path, text: str, label: str) -> None:
    require(not path.is_symlink(), f"{label} output is symlinked: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".staging", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def expected_case(case_name: str) -> tuple[str, int, str, str]:
    contract = evidence.CASE_CONTRACT.get(case_name)
    require(contract is not None, f"unknown R13 case name: {case_name}")
    return contract


def select_observer_event(
    rows: list[dict[str, object]], fixture_hash: str, label: str,
) -> dict[str, object]:
    targets = [row for row in rows if row.get("target") is True]
    require(len(targets) == 1,
            f"{label} must contain exactly one target-bound observer event")
    selected = dict(targets[0])
    require(selected.get("event_kind") == PERMISSION_EVENT_KIND,
            f"{label} target is not a FAN_OPEN_PERM event")
    event_id = selected.get("event_id")
    require(type(event_id) is int and event_id >= 1,
            f"{label} target has an invalid event ID")
    require(selected.get("fixture_sha256") == fixture_hash,
            f"{label} target is not bound to the requested fixture")
    path = selected.get("path")
    require(isinstance(path, str) and path.startswith("/"),
            f"{label} target has no resolved absolute path")
    require(selected.get("observer_response") == "FAN_ALLOW",
            f"{label} target lacks the recorder's FAN_ALLOW response")
    mask = selected.get("mask")
    require(type(mask) is int and mask & evidence.FAN_OPEN_PERM_MASK,
            f"{label} target lacks the FAN_OPEN_PERM mask")
    for field in ("event_pid", "event_len", "metadata_len", "metadata_version"):
        value = selected.get(field)
        require(type(value) is int and value >= 0,
                f"{label} target has an invalid {field}")
    return selected


def select_permission_record(
    rows: list[dict[str, object]], observer: dict[str, object],
    expected_response: str, label: str,
) -> dict[str, object]:
    seen_ids: set[int] = set()
    matches: list[dict[str, object]] = []
    for row in rows:
        require(row.get("artifact_kind") == PERMISSION_ARTIFACT_KIND,
                f"{label} has an invalid artifact kind")
        require(row.get("event_kind") == PERMISSION_EVENT_KIND,
                f"{label} has a non-permission event")
        event_id = row.get("clamonacc_event_id")
        require(type(event_id) is int and event_id >= 1 and event_id not in seen_ids,
                f"{label} has an invalid or duplicate clamonacc event ID")
        seen_ids.add(event_id)
        for field in ("path", "event_pid", "event_len", "metadata_len",
                      "metadata_version", "mask"):
            require(field in row, f"{label} lacks {field}")
        if all(row.get(field) == observer.get(field) for field in (
            "path", "event_pid", "event_len", "metadata_len",
            "metadata_version", "mask",
        )):
            matches.append(dict(row))
    require(len(matches) == 1,
            f"{label} does not have exactly one unambiguous match for the observer event")
    selected = matches[0]
    require(selected.get("permission_response") == expected_response,
            f"{label} matched event has the wrong permission response")
    require(selected.get("response_written") is True,
            f"{label} matched event did not record a completed response write")
    return selected


def validate_actor(
    rows: list[dict[str, object]], case_name: str, fixture_hash: str,
    event_id: int, expected_action: str, label: str,
) -> dict[str, object]:
    require(len(rows) == 1, f"{label} must contain one actor result")
    actor = dict(rows[0])
    require(actor.get("case_name") == case_name,
            f"{label} is not bound to case {case_name}")
    require(actor.get("fixture_sha256") == fixture_hash,
            f"{label} is not bound to the requested fixture")
    require(actor.get("event_id") == event_id,
            f"{label} is not bound to observer event {event_id}")
    opened = actor.get("opened")
    require(type(opened) is bool, f"{label} has no boolean open result")
    require(actor.get("observed_action") == expected_action and
            opened is (expected_action == "allow"),
            f"{label} contradicts the expected permission action")
    actor_uid = actor.get("actor_uid")
    require(type(actor_uid) is int and actor_uid > 0,
            f"{label} has an invalid non-root actor UID")
    exit_code = actor.get("actor_exit_code")
    require(type(exit_code) is int and (exit_code == 0) is opened,
            f"{label} has an exit code inconsistent with the open result")
    require(isinstance(actor.get("stderr"), str), f"{label} has no stderr capture")
    return actor


def validate_raw_report(
    report: dict[str, object], case_name: str, fixture_hash: str,
    clamonacc_event_id: int, expected_completion: str, label: str,
) -> None:
    require(report.get("version") == 1,
            f"{label} has an invalid report version")
    require(report.get("clamonacc_event_id") == clamonacc_event_id,
            f"{label} is not bound to clamonacc event {clamonacc_event_id}")
    for field in evidence.SCAN_REPORT_FIELDS:
        value = report.get(field)
        require(type(value) is int and value >= 0,
                f"{label} field {field} is not a non-negative integer")
    require(report["root_size"] > 0,
            f"{label} does not retain a positive scanned root size")
    require(report.get("completion") == expected_completion,
            f"{label} completion does not match case {case_name}")
    completion, exit_code, _decision, _response = evidence.CASE_CONTRACT[case_name]
    require(completion == expected_completion, "internal case completion mismatch")
    if expected_completion == "COMPLETE":
        require(report["status"] == 0 and report["verdict"] in (0, 1),
                f"{label} clean report is not successful")
        require(report.get("last_alert") in (None, "") and
                report.get("last_alert_offset") is None,
                f"{label} clean report contains an alert")
    elif case_name == "detection":
        require(report["verdict"] in (2, 3) and
                isinstance(report.get("last_alert"), str) and
                bool(report["last_alert"]),
                f"{label} detection report lacks an alert")
        offset = report.get("last_alert_offset")
        require(type(offset) is int and offset >= 0,
                f"{label} detection report lacks an alert offset")
    else:
        require(report["status"] != 0 and isinstance(report.get("reason"), str) and
                bool(report["reason"]),
                f"{label} failure report lacks a non-clean reason")
    require("case_name" not in report and "fixture_sha256" not in report and
            "scan_exit_code" not in report and "evidence_type" not in report,
            f"{label} is already case-bound; refuse to overwrite its identity")
    require(exit_code in (0, 1, 2), "internal case exit-code mismatch")
    require(require_digest(fixture_hash) == fixture_hash,
            "internal fixture digest mismatch")


def bind(
    case_name: str,
    fixture_sha256: str,
    observer_path: Path,
    permission_path: Path,
    actor_path: Path,
    report_path: Path,
    output_kernel_path: Path,
    output_actor_path: Path,
    output_report_path: Path,
) -> dict[str, object]:
    fixture_hash = require_digest(fixture_sha256)
    completion, exit_code, decision, response = expected_case(case_name)
    observer_path = require_input(observer_path, "observer kernel artifact")
    permission_path = require_input(permission_path, "clamonacc permission artifact")
    actor_path = require_input(actor_path, "actor artifact")
    report_path = require_input(report_path, "clamonacc report artifact")
    outputs = [output_kernel_path.resolve(), output_actor_path.resolve(), output_report_path.resolve()]
    require(len(set(outputs)) == len(outputs), "binder outputs must be distinct")
    inputs = {observer_path, permission_path, actor_path, report_path}
    require(not any(path in inputs for path in outputs),
            "binder outputs must not overwrite raw input artifacts")

    observer = select_observer_event(
        load_json_lines(observer_path, "observer kernel artifact"),
        fixture_hash, "observer kernel artifact",
    )
    permission = select_permission_record(
        load_json_lines(permission_path, "clamonacc permission artifact"),
        observer, response, "clamonacc permission artifact",
    )
    event_id = int(observer["event_id"])
    clamonacc_event_id = int(permission["clamonacc_event_id"])
    actor = validate_actor(
        load_json_lines(actor_path, "actor artifact"), case_name,
        fixture_hash, event_id, decision, "actor artifact",
    )
    raw_report = load_json_lines(report_path, "clamonacc report artifact")
    require(len(raw_report) == 1,
            "clamonacc report artifact must contain one report")
    validate_raw_report(
        raw_report[0], case_name, fixture_hash, clamonacc_event_id,
        completion, "clamonacc report artifact",
    )

    bound_kernel = dict(observer)
    bound_kernel.update({
        "permission_response": permission["permission_response"],
        "clamonacc_event_id": clamonacc_event_id,
    })
    bound_report = dict(raw_report[0])
    bound_report.update({
        "evidence_type": "on-access-scan",
        "case_name": case_name,
        "fixture_sha256": fixture_hash,
        "scan_exit_code": exit_code,
    })

    atomic_write(
        output_kernel_path,
        json.dumps(bound_kernel, sort_keys=True) + "\n",
        "bound kernel artifact",
    )
    atomic_write(
        output_actor_path,
        json.dumps(actor, sort_keys=True) + "\n",
        "bound actor artifact",
    )
    atomic_write(
        output_report_path,
        json.dumps(bound_report, sort_keys=True) + "\n",
        "bound scan report artifact",
    )

    evidence.validate_kernel_event_artifact(
        output_kernel_path, "bound kernel artifact", event_id,
        fixture_hash, response,
    )
    evidence.validate_actor_artifact(
        output_actor_path, "bound actor artifact", case_name, event_id,
        fixture_hash, decision,
    )
    evidence.validate_scan_report_artifact(
        output_report_path, "bound scan report artifact", case_name,
        fixture_hash, completion, exit_code, clamonacc_event_id,
    )
    return {
        "case_name": case_name,
        "event_id": event_id,
        "clamonacc_event_id": clamonacc_event_id,
        "fixture_sha256": fixture_hash,
        "permission_response": permission["permission_response"],
        "completion": completion,
        "scan_exit_code": exit_code,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-name", required=True)
    parser.add_argument("--fixture-sha256", required=True)
    parser.add_argument("--observer-kernel", type=Path, required=True)
    parser.add_argument("--clamonacc-permission", type=Path, required=True)
    parser.add_argument("--actor-result", type=Path, required=True)
    parser.add_argument("--clamonacc-report", type=Path, required=True)
    parser.add_argument("--output-kernel-event", type=Path, required=True)
    parser.add_argument("--output-actor-result", type=Path, required=True)
    parser.add_argument("--output-scan-report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = bind(
            args.case_name, args.fixture_sha256, args.observer_kernel,
            args.clamonacc_permission, args.actor_result,
            args.clamonacc_report, args.output_kernel_event,
            args.output_actor_result, args.output_scan_report,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"large-file fanotify case binder failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
