#!/usr/bin/env python3
"""Produce capability-bound acceptance records from service evidence.

This is intentionally a narrow producer, not a qualification shortcut.  It
only translates workload labels whose capability identity and case semantics
are explicit below.  Missing clean, detection, limit, parser, matcher, or
fanotify cases remain missing and therefore continue to block readiness.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import largefile_acceptance_cases as acceptance_cases
import largefile_service_workload_check as workload_check


# Only workloads with a direct, unambiguous capability identity are mapped.
# Other service workloads remain useful evidence but must not be silently
# relabeled as a different API or protocol.
WORKLOAD_CAPABILITIES: dict[str, tuple[str, str]] = {
    "production-clamscan": ("clamscan", "file"),
    "edge-clamscan-stdin": ("clamscan", "stdin"),
    "production_cvd_scanreport": ("clamd", "SCANREPORT"),
    "production_cvd_contscanreport": ("clamd", "CONTSCANREPORT"),
    "production_cvd_multiscanreport": ("clamd", "MULTISCANREPORT"),
    "production_cvd_allmatchscanreport": ("clamd", "ALLMATCHSCANREPORT"),
    "production_cvd_fildesreport": ("clamd", "FILDESREPORT"),
    "production_cvd_instreamreport": ("clamd", "INSTREAMREPORT"),
    "production_cvd_fildes": ("clamdscan", "fdpass"),
    "edge-clamdscan-stdin": ("clamdscan", "stream"),
    "edge_contscan": ("clamd", "CONTSCAN"),
    "edge_multiscan": ("clamd", "MULTISCAN"),
    "edge_allmatchscan": ("clamd", "ALLMATCHSCAN"),
    "edge_fildes": ("clamd", "FILDES"),
    "edge_instream": ("clamd", "INSTREAM"),
}

REPORT_NUMERIC_FIELDS = (
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


def safe_relative(out: Path, value: str, label: str) -> str:
    if not value or value == "-" or value.startswith("/"):
        fail(f"{label} is not a safe evidence path: {value!r}")
    candidate = (out / value).resolve()
    try:
        relative = candidate.relative_to(out.resolve())
    except ValueError as error:
        raise ValueError(f"{label} escapes the service evidence directory") from error
    require_file(candidate, label)
    return relative.as_posix()


def read_summary(out: Path) -> dict[str, str]:
    summary_path = require_file(out / "service-summary.txt", "service summary")
    values: dict[str, str] = {}
    for line in summary_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in values:
            fail(f"service summary duplicates {key}")
        values[key] = value
    required = {
        "service_qualification": "pass",
        "service_runtime_loader_binding": "pass",
        "service_temp_budget": "pass",
        "rss_budget_contract": "overall-stricter-than-pcre-phase",
    }
    for key, expected in required.items():
        if values.get(key) != expected:
            fail(f"service summary does not prove {key}={expected}")
    for key in ("rss_budget_kb", "pcre_rss_budget_kb", "post_pcre_rss_budget_kb",
                "service_temp_budget_bytes"):
        if not values.get(key, "").isdigit():
            fail(f"service summary has no numeric {key}")
    return values


def load_inputs(out: Path) -> dict[str, dict]:
    path = require_file(out / "provenance/service-inputs-before.json", "service input evidence")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(f"service input evidence is not JSON: {path}") from error
    if record.get("version") != 1 or set(record.get("inputs", {})) != workload_check.ROLES:
        fail("service input evidence has an invalid schema")
    inputs = record["inputs"]
    for role, value in inputs.items():
        if not isinstance(value, dict) or not workload_check.re.fullmatch(r"[0-9a-f]{64}", value.get("sha256", "")):
            fail(f"service input evidence has no valid SHA-256 for {role}")
    return inputs


def load_workloads(out: Path) -> list[dict[str, str]]:
    path = require_file(out / "provenance/service-workload-results.tsv", "service workload results")
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    if not rows and path.read_text(encoding="utf-8") != "\t".join(workload_check.WORKLOAD_HEADER) + "\n":
        fail("service workload results have an invalid header")
    if not rows:
        return []
    if list(rows[0]) != workload_check.WORKLOAD_HEADER:
        fail("service workload results have an invalid header")
    return rows


def load_oracle(out: Path) -> dict:
    return workload_check.load_oracle(require_file(
        out / "provenance/qualification-oracle.tsv", "qualification oracle"))


def verdict_name(value: object) -> str:
    if value in (0, 1):
        return "CLEAN" if value == 0 else "TRUSTED"
    if value in (2, 3):
        return "DETECTED"
    return "INCOMPLETE"


def case_suffix(completion: str) -> str:
    return {
        "COMPLETE": "clean-edge",
        "DETECTION_TERMINATED": "detection-edge",
        "LIMIT_INCOMPLETE": "limit-edge",
    }.get(completion, "")


def record_from_workload(
    out: Path,
    row: dict[str, str],
    capability: tuple[str, str],
    oracle: dict,
    inputs: dict[str, dict],
    source_hash: str,
    build_hash: str,
    config_hash: str,
    oracle_hash: str,
    database_hashes: dict[str, str],
    summary: dict[str, str],
) -> dict[str, str]:
    label = row["label"]
    role = row["role"]
    if role not in workload_check.ROLES:
        fail(f"mapped workload has invalid role: {label}")
    if row["kind"] == "oversize" or row["kind"] == "milter":
        fail(f"mapped workload cannot use special evidence kind: {label}")
    report_path = Path(out / row["report"])
    log_path = Path(out / row["log"])
    report = workload_check.load_report(report_path, label)
    oracle_row = oracle[role]
    workload_check.validate_report(report, label, oracle_row)
    workload_check.validate_log(log_path, label, oracle_row, row["check_offset"] == "yes")
    transport_status = int(row["status"])
    completion = str(report["completion"])
    signature = report.get("last_alert") or "-"
    offset_value = report.get("last_alert_offset")
    offset = str(offset_value) if type(offset_value) is int else "-"
    if row["kind"] == "report":
        # Direct structured-report probes return transport success after the
        # framed JSON was received.  The scan outcome lives in that JSON and
        # must be bound to the R04 record independently of probe status.
        if transport_status != 0:
            fail(f"{label} report transport did not complete successfully")
        status = {
            "COMPLETE": 0,
            "DETECTION_TERMINATED": 1,
            "LIMIT_INCOMPLETE": 2,
        }.get(completion, 2)
        workload_check.validate_outcome(label, status, completion, signature)
    else:
        status = transport_status
        workload_check.validate_outcome(label, status, completion, signature)
    suffix = case_suffix(completion)
    if not suffix:
        fail(f"mapped workload has no ingress case semantics: {label}:{completion}")
    kind, identifier = capability
    case_id = f"{kind}:{identifier}:{suffix}"
    reason = report.get("reason") or f"structured report completion {completion}"
    if not isinstance(reason, str) or not reason:
        fail(f"mapped workload has no report reason: {label}")
    if role not in inputs:
        fail(f"mapped workload lacks input identity: {label}")
    database_role = "edge" if role == "edge" else "production"
    fixture_hash = inputs[role].get("sha256")
    if not isinstance(fixture_hash, str) or len(fixture_hash) != 64:
        fail(f"mapped workload lacks fixture identity: {label}")
    artifacts = [
        safe_relative(out, row["log"], f"{label} log"),
        safe_relative(out, row["report"], f"{label} report"),
        "provenance/source-manifest.txt",
        "service-summary.txt",
        "provenance/service-build-identity.txt",
        "provenance/CMakeCache.txt",
        "provenance/service-inputs-before.json",
        "provenance/qualification-oracle.tsv",
        f"provenance/database-manifest-{database_role}-before.txt",
    ]
    return {
        "kind": kind,
        "id": identifier,
        "case_id": case_id,
        "source_manifest_sha256": source_hash,
        "build_identity_sha256": build_hash,
        "config_sha256": config_hash,
        "platform": f"{os.uname().sysname}-{os.uname().machine}",
        "fixture_role": role,
        "fixture_sha256": fixture_hash,
        "oracle_sha256": oracle_hash,
        "database_sha256": database_hashes[database_role],
        "exit_code": str(status),
        "verdict": verdict_name(report.get("verdict")),
        "completion": completion,
        "reason": reason,
        "alert_signature": signature,
        "alert_offset": offset,
        **{field: str(report[field]) for field in acceptance_cases.RECORD_HEADER
           if field in REPORT_NUMERIC_FIELDS},
        "sanitizer": "release",
        "resource_phase": (
            f"rss<={summary['rss_budget_kb']};"
            f"pcre<={summary['pcre_rss_budget_kb']};"
            f"post-pcre<={summary['post_pcre_rss_budget_kb']};"
            f"temporary<={summary['service_temp_budget_bytes']}"
        ),
        "health": "pass",
        "cleanup": "pass",
        "artifacts": ",".join(artifacts),
    }


def produce(
    out: Path,
    manifest: Path,
    mapping_path: Path,
    output: Path | None = None,
) -> int:
    out = out.resolve()
    mapping = acceptance_cases.validate_map(manifest, mapping_path)
    required = {
        (row["kind"], row["id"]): set(row["required_case_ids"].split(","))
        for row in mapping
    }
    summary = read_summary(out)
    inputs = load_inputs(out)
    oracle = load_oracle(out)
    workloads = load_workloads(out)
    source_manifest = require_file(out / "provenance/source-manifest.txt", "source manifest")
    build_identity = require_file(out / "provenance/service-build-identity.txt", "service build identity")
    config = require_file(out / "provenance/CMakeCache.txt", "CMake cache")
    oracle_file = require_file(out / "provenance/qualification-oracle.tsv", "qualification oracle")
    database_hashes = {
        role: sha256(require_file(
            out / f"provenance/database-manifest-{role}-before.txt",
            f"{role} database manifest"))
        for role in ("production", "edge")
    }
    source_hash = sha256(source_manifest)
    build_hash = sha256(build_identity)
    config_hash = sha256(config)
    oracle_hash = sha256(oracle_file)

    records: dict[tuple[str, str, str], dict[str, str]] = {}
    for row in workloads:
        capability = WORKLOAD_CAPABILITIES.get(row["label"])
        if capability is None:
            continue
        record = record_from_workload(
            out, row, capability, oracle, inputs, source_hash, build_hash,
            config_hash, oracle_hash, database_hashes, summary,
        )
        key = (record["kind"], record["id"], record["case_id"])
        if key in records:
            fail(f"multiple workloads claim one capability case: {':'.join(key)}")
        if record["case_id"] not in required.get((record["kind"], record["id"]), set()):
            fail(f"producer generated an unrequired case: {record['case_id']}")
        records[key] = record

    destination = (output or (out / "provenance/acceptance-cases.tsv")).resolve()
    try:
        destination.relative_to(out)
    except ValueError as error:
        raise ValueError("acceptance record output must be inside service evidence") from error
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = destination.with_name(f".{destination.name}.staging")
    with staging.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=acceptance_cases.RECORD_HEADER,
            delimiter="\t", lineterminator="\n",
        )
        writer.writeheader()
        for key in sorted(records):
            writer.writerow(records[key])
    os.replace(staging, destination)
    return len(records)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service_output", type=Path)
    parser.add_argument("--manifest", type=Path,
                        default=Path("docs/largefile-capabilities.tsv"))
    parser.add_argument("--map", dest="mapping", type=Path,
                        default=Path("docs/largefile-capability-case-map.tsv"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        count = produce(args.service_output, args.manifest, args.mapping, args.output)
        print(f"large-file acceptance case producer wrote {count} records")
        return 0
    except (OSError, ValueError, KeyError, csv.Error, json.JSONDecodeError) as error:
        print(f"large-file acceptance case producer failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
