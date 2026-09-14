#!/usr/bin/env python3
"""Validate and bind per-case resource measurements for release evidence.

The acceptance-case TSV records the scan result and its workload counters.
This sidecar records measurements that must come from an independent runtime
sampler.  Development evidence may omit the sidecar; authoritative release
readiness may not.  The sidecar is deliberately strict so a copied budget
label or a daemon-only measurement cannot stand in for a per-case process-tree
sample.
"""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import largefile_acceptance_cases as acceptance_cases


RESOURCE_HEADER = [
    "kind", "id", "case_id", "source_manifest_sha256",
    "build_identity_sha256", "config_sha256", "platform", "sample_source",
    "sample_count", "rss_peak_kb", "pss_peak_kb", "vas_peak_kb",
    "swap_peak_kb", "minor_faults_peak", "major_faults_peak",
    "read_bytes_peak", "write_bytes_peak", "cancelled_write_bytes_peak",
    "temporary_peak_bytes", "oom_events_peak", "oom_kill_events_peak",
    "oom_cgroup_count", "oom_cgroup_digest", "pcre_rss_peak_kb",
    "post_pcre_rss_peak_kb",
]
RESOURCE_PATH = "provenance/acceptance-case-resources.tsv"
RESOURCE_MARKER_RE = re.compile(r"resource-records=([0-9a-f]{64})\Z")
HASH_FIELDS = {
    "source_manifest_sha256", "build_identity_sha256", "config_sha256",
}
NONNEGATIVE_FIELDS = {
    "sample_count", "rss_peak_kb", "pss_peak_kb", "vas_peak_kb",
    "swap_peak_kb", "minor_faults_peak", "major_faults_peak",
    "read_bytes_peak", "write_bytes_peak", "cancelled_write_bytes_peak",
    "temporary_peak_bytes", "oom_events_peak", "oom_kill_events_peak",
    "oom_cgroup_count",
}
MAX_RSS_KB = 40 * 1024 * 1024
POST_PCRE_RSS_KB = 12 * 1024 * 1024
MAX_TEMP_BYTES = 64 * 1024 * 1024 * 1024


def fail(message: str) -> None:
    raise ValueError(message)


def sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_file(path: Path, label: str) -> Path:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} is missing or symlinked: {path}")
    return path


def read_resources(path: Path) -> list[dict[str, str]]:
    try:
        return acceptance_cases.read_tsv(path, RESOURCE_HEADER)
    except ValueError as error:
        raise ValueError(f"acceptance resource records are invalid: {error}") from error


def integer(value: str, field: str, line_number: int) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        fail(f"acceptance resource record has an invalid {field} at line {line_number}")
    return int(value)


def validate_resource_rows(
    rows: list[dict[str, str]],
    cases: dict[tuple[str, str, str], dict[str, str]],
    required_capabilities: tuple[tuple[str, str], ...] = (),
) -> None:
    seen: set[tuple[str, str, str]] = set()
    required_case_keys: set[tuple[str, str, str]] = set()
    for capability in required_capabilities:
        matching = [key for key in cases if key[:2] == capability]
        if not matching:
            fail(f"acceptance resource request has no cases for {capability[0]}:{capability[1]}")
        required_case_keys.update(matching)

    for line_number, row in enumerate(rows, start=2):
        key = (row["kind"], row["id"], row["case_id"])
        if key in seen:
            fail(f"acceptance resource records duplicate a case at line {line_number}")
        seen.add(key)
        case = cases.get(key)
        if case is None:
            fail(f"acceptance resource record names an unknown case at line {line_number}")
        for field in HASH_FIELDS:
            if not acceptance_cases.HASH_RE.fullmatch(row[field]):
                fail(f"acceptance resource record has an invalid {field} at line {line_number}")
            if row[field] != case[field]:
                fail(f"acceptance resource record {field} does not match its case at line {line_number}")
        if row["platform"] != case["platform"]:
            fail(f"acceptance resource record platform does not match its case at line {line_number}")
        if row["sample_source"] != "procfs-process-tree":
            fail(f"acceptance resource record does not use the approved process-tree sampler at line {line_number}")
        for field in NONNEGATIVE_FIELDS:
            integer(row[field], field, line_number)
        sample_count = int(row["sample_count"])
        rss = int(row["rss_peak_kb"])
        pss = int(row["pss_peak_kb"])
        vas = int(row["vas_peak_kb"])
        swap = int(row["swap_peak_kb"])
        temporary = int(row["temporary_peak_bytes"])
        if sample_count < 1:
            fail(f"acceptance resource record has no samples at line {line_number}")
        if not row["platform"].startswith("Linux-") or "x86_64" not in row["platform"]:
            fail(f"acceptance resource record is not from certified Linux x86-64 at line {line_number}")
        if rss > MAX_RSS_KB:
            fail(f"acceptance resource record RSS exceeds the 40 GiB ceiling at line {line_number}")
        if pss > rss:
            fail(f"acceptance resource record PSS exceeds RSS at line {line_number}")
        if vas < rss:
            fail(f"acceptance resource record VAS is below RSS at line {line_number}")
        if swap != 0:
            fail(f"acceptance resource record has nonzero swap at line {line_number}")
        if temporary > MAX_TEMP_BYTES:
            fail(f"acceptance resource record temporary usage exceeds 64 GiB at line {line_number}")
        oom_events = int(row["oom_events_peak"])
        oom_kill_events = int(row["oom_kill_events_peak"])
        if oom_events != 0 or oom_kill_events != 0:
            fail(f"acceptance resource record has an OOM event at line {line_number}")
        if not acceptance_cases.HASH_RE.fullmatch(row["oom_cgroup_digest"]):
            fail(f"acceptance resource record has an invalid oom_cgroup_digest at line {line_number}")
        if int(row["oom_cgroup_count"]) < 1:
            fail(f"acceptance resource record has no OOM cgroup sample at line {line_number}")

        pcre_peak = row["pcre_rss_peak_kb"]
        post_peak = row["post_pcre_rss_peak_kb"]
        is_pcre = key[:2] == ("matcher", "pcre")
        if is_pcre:
            pcre_value = integer(pcre_peak, "pcre_rss_peak_kb", line_number)
            post_value = integer(post_peak, "post_pcre_rss_peak_kb", line_number)
            if pcre_value > MAX_RSS_KB:
                fail(f"acceptance resource record PCRE RSS exceeds 40 GiB at line {line_number}")
            if post_value >= POST_PCRE_RSS_KB:
                fail(f"acceptance resource record post-PCRE RSS is not below 12 GiB at line {line_number}")
        elif pcre_peak != "-" or post_peak != "-":
            fail(f"non-PCRE acceptance resource record carries PCRE phase peaks at line {line_number}")

    missing = required_case_keys - seen
    if missing:
        fail(f"acceptance resource records are missing required cases: {sorted(missing)}")


def resource_marker(value: str) -> str | None:
    for token in value.split(";"):
        match = RESOURCE_MARKER_RE.fullmatch(token)
        if match:
            return match.group(1)
    return None


def validate(
    records_path: Path,
    evidence_root: Path,
    resources_path: Path | None = None,
    required_capabilities: tuple[tuple[str, str], ...] = (),
) -> int:
    records = acceptance_cases.read_tsv(records_path, acceptance_cases.RECORD_HEADER)
    cases = {
        (row["kind"], row["id"], row["case_id"]): row for row in records
    }
    if len(cases) != len(records):
        fail("acceptance case records duplicate a case")
    path = (resources_path or evidence_root / RESOURCE_PATH).resolve()
    root = evidence_root.resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError("acceptance resource records escape the evidence root") from error
    rows = read_resources(require_file(path, "acceptance resource records"))
    validate_resource_rows(rows, cases, required_capabilities)
    rows_by_key = {(row["kind"], row["id"], row["case_id"]): row for row in rows}
    resource_hash = sha256(path)
    target_keys = set(rows_by_key) if not required_capabilities else {
        key for key in cases if key[:2] in required_capabilities
    }
    for key in sorted(target_keys):
        case = cases.get(key)
        if case is None or key not in rows_by_key:
            fail(f"acceptance resource records are missing case {':'.join(key)}")
        marker = resource_marker(case["resource_phase"])
        if marker != resource_hash:
            fail(f"acceptance case does not bind the resource-record hash: {':'.join(key)}")
        if RESOURCE_PATH not in case["artifacts"].split(","):
            fail(f"acceptance case does not retain {RESOURCE_PATH}: {':'.join(key)}")
    return len(rows)


def bind(records_path: Path, evidence_root: Path, resources_path: Path | None = None) -> int:
    """Add the sidecar hash/path binding to every acceptance record."""
    records = acceptance_cases.read_tsv(records_path, acceptance_cases.RECORD_HEADER)
    path = (resources_path or evidence_root / RESOURCE_PATH).resolve()
    root = evidence_root.resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError("acceptance resource records escape the evidence root") from error
    rows = read_resources(require_file(path, "acceptance resource records"))
    cases: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in records:
        key = (row["kind"], row["id"], row["case_id"])
        if key in cases:
            fail(f"acceptance case records duplicate a case: {':'.join(key)}")
        cases[key] = row
    validate_resource_rows(rows, cases)
    row_keys = {(row["kind"], row["id"], row["case_id"]) for row in rows}
    case_keys = set(cases)
    if row_keys != case_keys:
        fail("acceptance resource records must cover every acceptance case before binding")
    resource_hash = sha256(path)
    for row in records:
        existing = [token for token in row["resource_phase"].split(";")
                    if token.startswith("resource-records=")]
        if existing and existing != [f"resource-records={resource_hash}"]:
            fail(f"acceptance case has a conflicting resource-record hash: {row['case_id']}")
        phases = [token for token in row["resource_phase"].split(";")
                  if not token.startswith("resource-records=")]
        phases.append(f"resource-records={resource_hash}")
        row["resource_phase"] = ";".join(phases)
        artifacts = row["artifacts"].split(",")
        if RESOURCE_PATH not in artifacts:
            artifacts.append(RESOURCE_PATH)
        row["artifacts"] = ",".join(artifacts)
    staging = records_path.with_name(f".{records_path.name}.resources-staging")
    with staging.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=acceptance_cases.RECORD_HEADER,
            delimiter="\t", lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(records)
    os.replace(staging, records_path)
    validate(records_path, root, path)
    return len(records)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_root", type=Path)
    parser.add_argument("--records", type=Path)
    parser.add_argument("--resources", type=Path)
    parser.add_argument("--bind", action="store_true")
    parser.add_argument("--require-capability", nargs=2, action="append", metavar=("KIND", "ID"))
    args = parser.parse_args(argv)
    root = args.evidence_root.resolve()
    records = (args.records or root / "provenance/acceptance-cases.tsv").resolve()
    resources_path = args.resources
    if resources_path is not None and not resources_path.is_absolute():
        resources_path = root / resources_path
    requested = tuple(tuple(item) for item in (args.require_capability or []))
    try:
        if args.bind:
            count = bind(records, root, resources_path)
        else:
            count = validate(records, root, resources_path, requested)
        print(f"large-file acceptance resource records passed ({count} rows)")
        return 0
    except (OSError, ValueError, csv.Error) as error:
        print(f"large-file acceptance resource records failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
