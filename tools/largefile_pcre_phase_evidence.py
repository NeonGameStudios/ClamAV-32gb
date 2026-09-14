#!/usr/bin/env python3
"""Validate retained PCRE full-subject and post-PCRE RSS evidence.

This verifier checks the R13 evidence contract only.  It does not run a scan,
sample a process, or infer RSS from counters.  A real qualification run must
retain the process-tree samples and the exact-tail scan artifacts named by the
proof document.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import re
import sys

import largefile_acceptance_cases as acceptance_cases

HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
PCRE_RSS_BUDGET_KB = 41943040
POST_PCRE_RSS_BUDGET_KB = 12582912
PHASES = ("before-pcre", "pcre", "post-pcre-before-deep-parse", "deep-parse")
IDENTITY_FIELDS = ("source_manifest", "build_identity", "config")


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


def validate_artifacts(root: Path, artifacts: object) -> None:
    required_roles = {"fixture", "rss-samples", "scan-report", "process-log"}
    require(isinstance(artifacts, list) and artifacts,
            "PCRE proof has no retained artifacts")
    seen_paths: set[str] = set()
    seen_roles: set[str] = set()
    for artifact in artifacts:
        require(isinstance(artifact, dict), "PCRE proof has an invalid artifact")
        path_text = artifact.get("path")
        role = artifact.get("role")
        require(isinstance(path_text, str) and path_text not in seen_paths,
                "PCRE proof has a duplicate or invalid artifact path")
        require(isinstance(role, str) and role not in seen_roles,
                "PCRE proof has a duplicate or invalid artifact role")
        seen_paths.add(path_text)
        seen_roles.add(role)
        path = relative_file(root, path_text, "PCRE artifact")
        expected = artifact.get("sha256")
        require(isinstance(expected, str) and HASH_RE.fullmatch(expected),
                f"PCRE artifact hash is invalid: {role}")
        require(digest(path) == expected,
                f"PCRE artifact hash does not verify: {role}")
    require(required_roles <= seen_roles,
            "PCRE proof lacks required retained artifacts: "
            f"{sorted(required_roles - seen_roles)}")


def validate_runtime_markers(root: Path, artifacts: object) -> None:
    require(isinstance(artifacts, list), "PCRE proof artifacts are invalid")
    process_logs = [artifact for artifact in artifacts
                    if isinstance(artifact, dict) and artifact.get("role") == "process-log"]
    require(len(process_logs) == 1, "PCRE proof must have one process-log artifact")
    process_log = relative_file(root, process_logs[0].get("path"),
                                "PCRE process-log artifact")
    lines = process_log.read_text(encoding="utf-8").splitlines()
    required = (
        "largefile_pcre_phase: phase=before-pcre ",
        "largefile_pcre_phase: phase=pcre ",
        "largefile_pcre_phase: phase=post-pcre-before-deep-parse ",
        "largefile_pcre_phase: phase=deep-parse ",
    )
    positions = []
    for marker in required:
        matches = [index for index, line in enumerate(lines) if marker in line]
        require(matches, f"PCRE process log lacks runtime marker: {marker.strip()}")
        positions.append(matches[0])
    require(positions == sorted(positions),
            "PCRE runtime phase markers are out of order")

    post_line = lines[positions[2]]
    deep_line = lines[positions[3]]
    require("subject_released=1" in post_line,
            "PCRE process log does not record subject release")
    require("subject_released=1" in deep_line,
            "PCRE process log does not bind deep parsing after release")


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
    integer(subject.get("expected_offset"), "expected offset")
    require(subject.get("detected_offset") == subject.get("expected_offset"),
            "PCRE subject did not prove the exact expected offset")
    require(subject.get("completion") == "DETECTION_TERMINATED" and
            subject.get("exit_code") == 1,
            "PCRE subject did not prove a detection-terminated result")


def validate_process_tree(process_tree: object) -> None:
    require(isinstance(process_tree, dict), "PCRE process-tree evidence is invalid")
    integer(process_tree.get("root_pid"), "root PID", 1)
    sampled_pids = process_tree.get("sampled_pids")
    require(isinstance(sampled_pids, list) and sampled_pids and
            all(type(pid) is int and pid >= 1 for pid in sampled_pids),
            "PCRE sampled PID set is invalid")
    require(process_tree.get("sample_source") == "procfs-tree",
            "PCRE samples are not identified as process-tree RSS")
    require(isinstance(process_tree.get("sampler"), str) and
            process_tree["sampler"].startswith("/"),
            "PCRE sampler identity is missing")


def validate_samples(samples: object) -> None:
    require(isinstance(samples, list) and samples,
            "PCRE proof has no RSS samples")
    seen_sequences: set[int] = set()
    seen_phases: set[str] = set()
    previous_sequence = 0
    previous_timestamp = 0
    for sample in samples:
        require(isinstance(sample, dict), "PCRE RSS sample is not an object")
        sequence = integer(sample.get("sequence"), "sample sequence", 1)
        timestamp = integer(sample.get("timestamp_ns"), "sample timestamp", 1)
        require(sequence not in seen_sequences and sequence > previous_sequence,
                "PCRE RSS sample sequence is not strictly ordered")
        require(timestamp > previous_timestamp,
                "PCRE RSS sample timestamps are not strictly ordered")
        phase = sample.get("phase")
        require(isinstance(phase, str) and phase in PHASES,
                "PCRE RSS sample has an unknown phase")
        rss = integer(sample.get("rss_kb"), "RSS")
        tree_rss = integer(sample.get("tree_rss_kb"), "tree RSS")
        require(tree_rss >= rss,
                "PCRE tree RSS is smaller than the process RSS")
        if phase == "pcre":
            require(tree_rss <= PCRE_RSS_BUDGET_KB,
                    "PCRE phase tree RSS exceeds the 40 GiB budget")
        if phase == "post-pcre-before-deep-parse":
            require(tree_rss < POST_PCRE_RSS_BUDGET_KB,
                    "post-PCRE tree RSS does not fall below the 12 GiB budget")
        seen_sequences.add(sequence)
        seen_phases.add(phase)
        previous_sequence = sequence
        previous_timestamp = timestamp
    require(seen_phases == set(PHASES),
            "PCRE RSS samples do not cover every required phase")


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
    require(document.get("proof_format_version") == 1 and
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
    validate_identity(root, document.get("identity"), source_hash)
    validate_subject(document.get("subject"))
    validate_process_tree(document.get("process_tree"))
    validate_samples(document.get("samples"))
    validate_transition(document.get("transition"))
    validate_artifacts(root, document.get("artifacts"))
    validate_runtime_markers(root, document.get("artifacts"))
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
