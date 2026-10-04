#!/usr/bin/env python3
"""Validate retained PCRE full-subject and post-PCRE RSS evidence.

This verifier checks the R13 evidence contract only.  It does not run a scan,
sample a process, or infer RSS from counters.  A real qualification run must
retain the process-tree samples and the exact-tail scan artifacts named by the
proof document.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

import largefile_acceptance_cases as acceptance_cases
import largefile_acceptance_resources as acceptance_resources

HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
PCRE_RSS_BUDGET_KB = 41943040
POST_PCRE_RSS_BUDGET_KB = 12582912
EXACT_SIZE_BYTES = 32 * 1024 * 1024 * 1024
DETECTION_PHASES = ("before-pcre", "pcre", "post-pcre-before-deep-parse")
CONTINUATION_PHASES = DETECTION_PHASES + ("deep-parse",)
TRACE_PHASES = CONTINUATION_PHASES + ("complete",)
IDENTITY_FIELDS = ("source_manifest", "build_identity")
RUNTIME_MARKER_RE = re.compile(
    r"(?:LibClamAV debug: )?largefile_pcre_phase: phase=(?P<phase>[^ ]+) "
    r"object_id=(?P<object_id>[0-9]+) "
    r"recursion_level=(?P<recursion_level>[0-9]+)"
    r"(?: subject_bytes=(?P<subject_bytes>[0-9]+))? "
    r"subject_released=(?P<subject_released>[01])\Z"
)
PCRE_MATCH_RE = re.compile(
    r"(?:LibClamAV debug: )?cli_pcre_scanbuf: located regex match @ (?P<offset>[0-9]+)\Z"
)


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


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
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"{label} escapes the evidence root") from error
    return candidate.resolve()


def validate_identity(root: Path, identity: object, expected_source: str) -> None:
    require(isinstance(identity, dict), "PCRE identity evidence is invalid")
    for field in IDENTITY_FIELDS:
        record = identity.get(field)
        require(isinstance(record, dict), f"PCRE identity lacks {field}")
        path = relative_file(root, record.get("path"), f"PCRE {field} path")
        expected = record.get("sha256")
        require(isinstance(expected, str) and HASH_RE.fullmatch(expected),
                f"PCRE {field} hash is invalid")
        require(digest(path) == expected,
                f"PCRE {field} hash does not verify")
        if field == "source_manifest":
            require(expected == expected_source,
                    "PCRE source manifest hash is not the proof binding")
        elif field == "build_identity":
            cache = path.read_text(encoding="utf-8").splitlines()
            wanted = {
                "CLAMAV_SOURCE_COMMIT": expected_source,
                "CLAMAV_SOURCE_MANIFEST_SHA256": expected_source,
            }
            for key, value in wanted.items():
                rows = [line for line in cache if line.startswith(key + ":INTERNAL=")]
                require(len(rows) == 1 and rows[0].split("=", 1)[1] == value,
                        f"PCRE build identity does not bind {key} to source")


def validate_artifacts(root: Path, artifacts: object) -> dict[str, tuple[Path, str]]:
    required_roles = {"fixture", "scanner-binary"}
    for run in ("detection", "continuation"):
        required_roles.update({f"{run}-config", f"{run}-database",
                               f"{run}-rss-samples", f"{run}-scan-report",
                               f"{run}-process-log", f"{run}-resource-row",
                               f"{run}-phase-events"})
    require(isinstance(artifacts, list) and artifacts,
            "PCRE proof has no retained artifacts")
    seen_paths: set[str] = set()
    verified: dict[str, tuple[Path, str]] = {}
    for artifact in artifacts:
        require(isinstance(artifact, dict), "PCRE proof has an invalid artifact")
        path_text = artifact.get("path")
        role = artifact.get("role")
        require(isinstance(path_text, str) and path_text not in seen_paths,
                "PCRE proof has a duplicate or invalid artifact path")
        require(isinstance(role, str) and role not in verified,
                "PCRE proof has a duplicate or invalid artifact role")
        seen_paths.add(path_text)
        if role == "fixture" and path_text.startswith("/"):
            path = Path(path_text)
            require(path.is_file() and not path.is_symlink() and
                    stat.S_ISREG(path.stat().st_mode),
                    "PCRE fixture is missing, symlinked, or not a regular file")
        else:
            path = relative_file(root, path_text, "PCRE artifact")
        expected = artifact.get("sha256")
        require(isinstance(expected, str) and HASH_RE.fullmatch(expected),
                f"PCRE artifact hash is invalid: {role}")
        require(digest(path) == expected,
                f"PCRE artifact hash does not verify: {role}")
        verified[role] = (path, expected)
    require(required_roles <= verified.keys(),
            "PCRE proof lacks required retained artifacts: "
            f"{sorted(required_roles - verified.keys())}")
    require(verified["detection-database"][1] != verified["continuation-database"][1],
            "PCRE detection and continuation databases must be distinct")
    return verified


def validate_fixture(path: Path) -> None:
    stat = path.stat()
    require(stat.st_size == EXACT_SIZE_BYTES,
            "PCRE fixture is not an exact 32-GiB file")
    require(stat.st_blocks * 512 >= EXACT_SIZE_BYTES,
            "PCRE fixture is not fully allocated")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        require(os.lseek(descriptor, 0, os.SEEK_DATA) == 0 and
                os.lseek(descriptor, 0, os.SEEK_HOLE) == EXACT_SIZE_BYTES,
                "PCRE fixture has a sparse extent")
    finally:
        os.close(descriptor)


def validate_runtime_markers(process_log: Path, phases: tuple[str, ...],
                             run: str) -> None:
    lines = process_log.read_text(encoding="utf-8").splitlines()
    grouped: dict[tuple[int, int], list[tuple[int, str, int | None, bool]]] = {}
    for index, line in enumerate(lines):
        match = RUNTIME_MARKER_RE.fullmatch(line)
        if not match:
            continue
        key = (int(match.group("object_id")), int(match.group("recursion_level")))
        grouped.setdefault(key, []).append((
            index,
            match.group("phase"),
            int(match.group("subject_bytes")) if match.group("subject_bytes") else None,
            match.group("subject_released") == "1",
        ))

    require(grouped, "PCRE process log lacks object-bound runtime markers")
    for events in grouped.values():
        selected: list[tuple[int, str, int | None, bool]] = []
        previous_position = -1
        for phase in phases:
            candidate = next(
                (event for event in events
                 if event[0] > previous_position and event[1] == phase),
                None,
            )
            if candidate is None:
                selected = []
                break
            selected.append(candidate)
            previous_position = candidate[0]
        if len(selected) == len(phases):
            before, pcre, post = selected[:3]
            subject_bytes = [event[2] for event in (before, pcre, post)]
            valid = (subject_bytes == [EXACT_SIZE_BYTES] * 3 and
                     not before[3] and not pcre[3] and post[3])
            if run == "continuation":
                valid = valid and selected[3][3]
            if valid:
                return

    require(False, f"PCRE {run} process log lacks a valid object-bound runtime marker sequence or markers are out of order")


def validate_match_offset(process_log: Path, subject: dict) -> None:
    offsets = [int(match.group("offset"))
               for line in process_log.read_text(encoding="utf-8").splitlines()
               if (match := PCRE_MATCH_RE.fullmatch(line))]
    require(subject["expected_offset"] in offsets,
            "PCRE detection process log lacks the exact-tail regex match offset")


def integer(value: object, label: str, minimum: int = 0) -> int:
    require(type(value) is int and value >= minimum,
            f"PCRE {label} is invalid")
    return value


def validate_subject(subject: object) -> None:
    require(isinstance(subject, dict), "PCRE subject proof is invalid")
    require(subject.get("case_id") == "matcher:pcre:full-subject-tail",
            "PCRE subject proof has the wrong case ID")
    fixture_hash = subject.get("fixture_sha256")
    require(isinstance(fixture_hash, str) and HASH_RE.fullmatch(fixture_hash),
            "PCRE subject fixture hash is invalid")
    expected_signature = subject.get("expected_signature")
    require(isinstance(expected_signature, str) and expected_signature,
            "PCRE subject expected signature is missing")
    require(subject.get("detected_signature") == expected_signature,
            "PCRE subject did not prove the exact expected signature")
    expected_offset = integer(subject.get("expected_offset"), "expected offset")
    require(EXACT_SIZE_BYTES - 1024 * 1024 <= expected_offset < EXACT_SIZE_BYTES,
            "PCRE expected offset is not at the exact tail")
    require(subject.get("detected_offset") == subject.get("expected_offset"),
            "PCRE subject did not prove the exact expected offset")
    require(subject.get("completion") == "DETECTION_TERMINATED" and
            subject.get("exit_code") == 1,
            "PCRE subject did not prove a detection-terminated result")


def validate_continuation(continuation: object, subject: dict) -> None:
    require(isinstance(continuation, dict), "PCRE continuation proof is invalid")
    require(continuation.get("case_id") == "matcher:pcre:full-subject-release",
            "PCRE continuation has the wrong case ID")
    require(continuation.get("fixture_sha256") == subject.get("fixture_sha256"),
            "PCRE continuation does not use the detection fixture")
    require(continuation.get("completion") == "COMPLETE" and
            continuation.get("exit_code") == 0,
            "PCRE continuation did not complete cleanly")


SAMPLE_HEADER = (
    "sequence", "timestamp_ns", "phase", "rss_kb", "tree_rss_kb",
    "process_count", "root_pid", "sampled_pids",
)


def decimal(value: str, label: str, minimum: int = 0) -> int:
    require(bool(re.fullmatch(r"[0-9]+", value)), f"PCRE {label} is invalid")
    result = int(value)
    require(result >= minimum, f"PCRE {label} is invalid")
    return result


def validate_one_samples(path: Path, phases: tuple[str, ...], run: str) -> dict[str, int]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        rows = list(csv.reader(stream, delimiter="\t"))
    require(bool(rows) and tuple(rows[0]) == SAMPLE_HEADER,
            f"PCRE {run} raw RSS trace has the wrong header")
    require(len(rows) > 1, f"PCRE {run} proof has no RSS samples")
    seen_phases: set[str] = set()
    previous_sequence = 0
    previous_timestamp = 0
    previous_phase_index = 0
    root_pid = 0
    peaks = {"rss_peak_kb": 0, "pcre_rss_peak_kb": 0,
             "post_pcre_rss_peak_kb": 0}
    for fields in rows[1:]:
        require(len(fields) == len(SAMPLE_HEADER),
                f"PCRE {run} raw RSS trace has a malformed row")
        sample = dict(zip(SAMPLE_HEADER, fields))
        sequence = decimal(sample["sequence"], "sample sequence", 1)
        timestamp = decimal(sample["timestamp_ns"], "sample timestamp", 1)
        require(sequence == previous_sequence + 1,
                "PCRE RSS sample sequence is not strictly ordered")
        require(timestamp > previous_timestamp,
                "PCRE RSS sample timestamps are not strictly ordered")
        phase = sample.get("phase")
        require(phase in TRACE_PHASES,
                "PCRE RSS sample has an unknown phase")
        phase_index = TRACE_PHASES.index(phase)
        require(phase_index >= previous_phase_index,
                "PCRE RSS sample phases are out of order")
        rss = decimal(sample["rss_kb"], "RSS")
        tree_rss = decimal(sample["tree_rss_kb"], "tree RSS")
        require(tree_rss >= rss,
                "PCRE tree RSS is smaller than the process RSS")
        count = decimal(sample["process_count"], "process count", 1)
        sample_root = decimal(sample["root_pid"], "root PID", 1)
        pids = [decimal(pid, "sampled PID", 1)
                for pid in sample["sampled_pids"].split(",")]
        require(len(pids) == count and len(set(pids)) == count and
                sample_root in pids,
                "PCRE process-tree PID trace is inconsistent")
        if root_pid == 0:
            root_pid = sample_root
        require(sample_root == root_pid,
                "PCRE process-tree root PID changes within one run")
        peaks["rss_peak_kb"] = max(peaks["rss_peak_kb"], tree_rss)
        if phase == "pcre":
            peaks["pcre_rss_peak_kb"] = max(peaks["pcre_rss_peak_kb"], tree_rss)
            require(tree_rss <= PCRE_RSS_BUDGET_KB,
                    "PCRE phase tree RSS exceeds the 40 GiB budget")
        if phase == "post-pcre-before-deep-parse":
            peaks["post_pcre_rss_peak_kb"] = max(
                peaks["post_pcre_rss_peak_kb"], tree_rss)
            require(tree_rss < POST_PCRE_RSS_BUDGET_KB,
                    "post-PCRE tree RSS does not fall below the 12 GiB budget")
        seen_phases.add(phase)
        previous_sequence = sequence
        previous_timestamp = timestamp
        previous_phase_index = phase_index
    require(set(phases) <= seen_phases,
            f"PCRE {run} RSS samples do not cover every required phase")
    return {**peaks, "root_pid": root_pid, "sample_count": len(rows) - 1,
            "first_timestamp_ns": decimal(rows[1][1], "first timestamp", 1),
            "last_timestamp_ns": previous_timestamp}


def validate_samples(artifacts: dict[str, tuple[Path, str]]) -> dict[str, dict[str, int]]:
    results = {}
    for run, phases in (("detection", DETECTION_PHASES),
                        ("continuation", CONTINUATION_PHASES)):
        results[run] = validate_one_samples(
            artifacts[f"{run}-rss-samples"][0], phases, run)
    require(results["detection"]["root_pid"] != results["continuation"]["root_pid"],
            "PCRE detection and continuation must be distinct processes")
    require(results["detection"]["last_timestamp_ns"] <
            results["continuation"]["first_timestamp_ns"],
            "PCRE detection and continuation trace times overlap")
    return results


def validate_configs(artifacts: dict[str, tuple[Path, str]],
                     identity: dict, source_hash: str) -> dict[str, dict]:
    configs = {}
    fixture = artifacts["fixture"][0]
    for run, case_id in (("detection", "matcher:pcre:full-subject-tail"),
                         ("continuation", "matcher:pcre:full-subject-release")):
        config = acceptance_cases.load_json(
            artifacts[f"{run}-config"][0].read_text(encoding="utf-8"),
            f"PCRE {run} config")
        require(isinstance(config, dict) and config.get("case_id") == case_id,
                f"PCRE {run} configuration has the wrong case ID")
        require(config.get("source_manifest_sha256") == source_hash and
                config.get("build_identity_sha256") ==
                identity["build_identity"]["sha256"],
                f"PCRE {run} configuration does not bind source and build")
        require(config.get("scanner_sha256") == artifacts["scanner-binary"][1] and
                config.get("database_sha256") == artifacts[f"{run}-database"][1] and
                config.get("fixture_sha256") == artifacts["fixture"][1],
                f"PCRE {run} configuration does not bind scanner, database and fixture")
        for field, expected in (("fixture", fixture),
                                ("database", artifacts[f"{run}-database"][0])):
            raw = config.get(field)
            require(isinstance(raw, str) and Path(raw).is_absolute() and
                    Path(raw).resolve() == expected.resolve(),
                    f"PCRE {run} configuration has the wrong {field} path")
        scanner = config.get("scanner")
        require(isinstance(scanner, str) and Path(scanner).is_absolute() and
                Path(scanner).is_file() and not Path(scanner).is_symlink() and
                digest(Path(scanner)) == artifacts["scanner-binary"][1],
                f"PCRE {run} scanner binary does not match retained artifact")
        args = config.get("args")
        require(isinstance(args, list) and all(isinstance(arg, str) for arg in args)
                and args and args[-1] == config["fixture"] and
                f"--database={config['database']}" in args and
                "--debug" in args and "--allmatch" in args and
                "--max-filesize=32G" in args and
                "--max-contiguous-size=32G" in args and
                "--pcre-max-filesize=32G" in args,
                f"PCRE {run} command arguments do not prove the exact-size scan")
        configs[run] = config
    return configs


def validate_resource_rows(artifacts: dict[str, tuple[Path, str]],
                           samples: dict[str, dict[str, int]],
                           source_hash: str, build_hash: str,
                           platform: str) -> None:
    for run, case in (("detection", "full-subject-tail"),
                      ("continuation", "full-subject-release")):
        rows = acceptance_resources.read_resources(
            artifacts[f"{run}-resource-row"][0])
        require(len(rows) == 1, f"PCRE {run} resource sidecar is not one row")
        row = rows[0]
        require((row["kind"], row["id"], row["case_id"]) ==
                ("matcher", "pcre", case),
                f"PCRE {run} resource sidecar has the wrong case")
        require(row["source_manifest_sha256"] == source_hash and
                row["build_identity_sha256"] == build_hash and
                row["config_sha256"] == artifacts[f"{run}-config"][1] and
                row["platform"] == platform,
                f"PCRE {run} resource sidecar does not bind source, build, config and platform")
        require(row["sample_source"] == "procfs-process-tree",
                f"PCRE {run} resource sidecar is not procfs-tree sampling")
        acceptance_resources.validate_resource_rows(
            [row], {(row["kind"], row["id"], row["case_id"]): row})
        for field in ("sample_count", "rss_peak_kb", "pcre_rss_peak_kb",
                      "post_pcre_rss_peak_kb"):
            require(decimal(row[field], field) == samples[run][field],
                    f"PCRE {run} resource {field} differs from raw RSS trace")


def validate_phase_events(artifacts: dict[str, tuple[Path, str]]) -> None:
    for run in ("detection", "continuation"):
        events = artifacts[f"{run}-phase-events"][0].read_text(
            encoding="utf-8").splitlines()
        allowed = (["pcre-start", "post-pcre", "complete"],
                   ["pcre-start", "post-pcre", "deep-parse", "complete"])
        require(events in (allowed if run == "detection" else allowed[1:]),
                f"PCRE {run} phase rendezvous is missing or out of order")


def validate_reports(subject: dict, continuation: dict,
                     artifacts: dict[str, tuple[Path, str]],
                     configs: dict[str, dict]) -> None:
    for run, expected in (("detection", subject), ("continuation", continuation)):
        lines = artifacts[f"{run}-scan-report"][0].read_text(encoding="utf-8").splitlines()
        require(len(lines) == 1, f"PCRE {run} must retain exactly one scan report")
        report = acceptance_cases.load_json(lines[0], f"PCRE {run} scan report")
        require(isinstance(report, dict) and
                report.get("completion") == expected["completion"] and
                report.get("target") == configs[run]["fixture"] and
                report.get("root_size") == EXACT_SIZE_BYTES and
                type(report.get("contiguous_bytes")) is int and
                report["contiguous_bytes"] == EXACT_SIZE_BYTES and
                report.get("skipped_operations") == 0,
                f"PCRE {run} report does not prove a full exact-size subject")
        if run == "detection":
            require(report.get("last_alert") == subject["expected_signature"] and
                    report.get("status") == 0 and report.get("verdict") == 2,
                    "PCRE detection report lacks exact expected alert")
        else:
            require(report.get("status") == 0 and report.get("verdict") == 0 and
                    not report.get("last_alert") and
                    report.get("skipped_operations") == 0,
                    "PCRE continuation report is not clean and complete")


def validate_transition(transition: object) -> None:
    require(isinstance(transition, dict), "PCRE phase transition evidence is invalid")
    require(transition.get("subject_released") is True,
            "PCRE proof does not observe full-subject release")
    require(transition.get("deep_parse_started_after_release") is True,
            "PCRE proof does not order deep parsing after subject release")
    require(transition.get("phase_markers_are_runtime_events") is True,
            "PCRE phase markers are not identified as runtime events")


def validate(proof_path: Path, evidence_root: Path | None = None) -> dict:
    proof_candidate = Path(proof_path)
    root = (evidence_root or proof_candidate.parent.parent).resolve()
    require(proof_candidate.is_file() and not proof_candidate.is_symlink(),
            "PCRE phase evidence proof is missing or symlinked")
    document = acceptance_cases.load_json(
        proof_candidate.read_text(encoding="utf-8"),
        "PCRE phase evidence proof",
    )
    require(isinstance(document, dict), "PCRE phase evidence proof is not an object")
    require(document.get("proof_format_version") == 2 and
            document.get("evidence_type") == "pcre-rss-phases" and
            document.get("qualification_result") == "pass",
            "PCRE phase evidence proof format is invalid")
    require(document.get("capability_kind") == "matcher" and
            document.get("capability_id") == "pcre",
            "PCRE phase evidence is not bound to matcher:pcre")
    source_hash = document.get("source_manifest_sha256")
    require(isinstance(source_hash, str) and HASH_RE.fullmatch(source_hash),
            "PCRE source manifest proof hash is invalid")
    require(document.get("platform", "").startswith("Linux-"),
            "PCRE phase evidence platform is not Linux")
    budgets = document.get("budgets")
    require(isinstance(budgets, dict) and
            budgets.get("pcre_rss_budget_kb") == PCRE_RSS_BUDGET_KB and
            budgets.get("post_pcre_rss_budget_kb") == POST_PCRE_RSS_BUDGET_KB,
            "PCRE phase evidence budgets do not match PLAN.md")
    artifacts = validate_artifacts(root, document.get("artifacts"))
    validate_fixture(artifacts["fixture"][0])
    identity = document.get("identity")
    validate_identity(root, identity, source_hash)
    subject = document.get("subject")
    validate_subject(subject)
    require(subject["fixture_sha256"] == artifacts["fixture"][1],
            "PCRE subject fixture hash does not bind retained fixture")
    continuation = document.get("continuation")
    validate_continuation(continuation, subject)
    configs = validate_configs(artifacts, identity, source_hash)
    validate_reports(subject, continuation, artifacts, configs)
    samples = validate_samples(artifacts)
    validate_resource_rows(artifacts, samples, source_hash,
                           identity["build_identity"]["sha256"],
                           document["platform"])
    validate_phase_events(artifacts)
    validate_transition(document.get("transition"))
    for run, phases in (("detection", DETECTION_PHASES),
                        ("continuation", CONTINUATION_PHASES)):
        validate_runtime_markers(artifacts[f"{run}-process-log"][0], phases, run)
    validate_match_offset(artifacts["detection-process-log"][0], subject)
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("proof", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    args = parser.parse_args(argv)
    try:
        validate(args.proof, args.evidence_root)
    except (OSError, ValueError, TypeError) as error:
        print(f"large-file PCRE phase evidence failed: {error}", file=sys.stderr)
        return 1
    print("large-file PCRE phase evidence passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
