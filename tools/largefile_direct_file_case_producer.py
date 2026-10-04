#!/usr/bin/env python3
"""Produce one R04 clamscan:file case from a fresh copy-free capture root.

Inputs, oracle, command result and measured resources must already be retained
by the pre-scan capture and procfs resource wrapper. This tool does not run a
scanner, invent a resource sample, or promote an incomplete case matrix.
"""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import largefile_acceptance_cases as cases
import largefile_acceptance_resources as resources


NUMERIC_REPORT_FIELDS = (
    "logical_bytes", "matcher_bytes", "contiguous_bytes", "temporary_bytes",
    "files_scanned", "max_recursion_depth", "elapsed_ms", "parser_operations",
    "detector_operations", "skipped_operations",
)
ARTIFACTS = (
    "provenance/source-content.sha256", "provenance/clamscan",
    "provenance/CMakeCache.txt", "provenance/database.ndb",
    "provenance/direct-oracle.json", "provenance/direct-inputs-before.json",
    "provenance/direct-inputs-after.json", "provenance/direct-command-result.json",
    "scan-report.jsonl", "provenance/scan.log", "provenance/samples.tsv",
)
SUFFIX_COMPLETIONS = {
    "clean-edge": ("COMPLETE", 0),
    "detection-edge": ("DETECTION_TERMINATED", 1),
    "limit-edge": ("LIMIT_INCOMPLETE", 2),
}


def fail(message: str) -> None:
    raise ValueError(message)


def file(root: Path, relative: str) -> Path:
    return cases.safe_evidence_file(root, relative, "direct case artifact")


def json_file(root: Path, relative: str) -> dict:
    return cases.load_json_object(file(root, relative).read_text(encoding="utf-8"), relative)


def one_report(root: Path) -> dict:
    lines = [line for line in file(root, "scan-report.jsonl").read_text(
        encoding="utf-8").splitlines() if line.strip()]
    if len(lines) != 1:
        fail("direct case must have exactly one structured report")
    return cases.load_json_object(lines[0], "direct scan report")


def validate_oracle(oracle: dict, identity: dict, artifact_hashes: dict[str, str]) -> tuple[str, str, str, str]:
    case_id = oracle.get("case_id")
    suffix = case_id.rsplit(":", 1)[-1] if isinstance(case_id, str) else ""
    expected = SUFFIX_COMPLETIONS.get(suffix)
    if case_id != f"clamscan:file:{suffix}" or expected is None:
        fail("direct oracle has an unsupported capability case")
    completion, exit_code = expected
    if type(oracle.get("version")) is not int or oracle["version"] != 1 or \
            oracle.get("fixture_role") in (None, "", "-") or \
            oracle.get("input") != identity.get("input") or \
            type(oracle.get("size")) is not int or oracle["size"] != identity.get("size") or \
            oracle.get("sha256") != identity.get("sha256") or \
            oracle.get("completion") != completion or \
            type(oracle.get("exit_code")) is not int or oracle["exit_code"] != exit_code:
        fail("direct oracle contradicts its pre-scan input or outcome contract")
    for field, relative in (
        ("source_manifest_sha256", "provenance/source-content.sha256"),
        ("build_identity_sha256", "provenance/clamscan"),
        ("config_sha256", "provenance/CMakeCache.txt"),
        ("database_sha256", "provenance/database.ndb"),
    ):
        if oracle.get(field) != artifact_hashes[relative]:
            fail(f"direct oracle does not bind {field}")
    signature = oracle.get("alert_signature")
    offset = oracle.get("alert_offset")
    offset_scope = oracle.get("alert_offset_scope")
    if completion == "DETECTION_TERMINATED":
        if not isinstance(signature, str) or signature in ("", "-") or \
                type(offset) is not int or offset < 0 or \
                offset_scope not in {"root-input", "nested-member"}:
            fail("direct detection oracle lacks an exact signature/offset scope")
    elif signature != "-" or offset is not None or offset_scope != "none":
        fail("direct non-detection oracle carries an alert")
    reason = oracle.get("reason")
    if not isinstance(reason, str) or not reason or "\n" in reason or "\t" in reason:
        fail("direct oracle lacks a valid reason")
    if completion == "LIMIT_INCOMPLETE" and reason != "Heuristics.Limits.Exceeded.MaxFileSize":
        fail("direct limit oracle has the wrong reason")
    return case_id, completion, reason, offset_scope


def validate_command(root: Path, command_result: dict, identity: dict,
                     oracle_hash: str, case_id: str, scanner_hash: str) -> int:
    if type(command_result.get("version")) is not int or command_result["version"] != 1 or \
            command_result.get("input_stable") is not True or \
            command_result.get("oracle_sha256") != oracle_hash or \
            type(command_result.get("exit_code")) is not int:
        fail("direct command result is missing stable-input/oracle evidence")
    argv = command_result.get("command")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv) or \
            argv.count("--") != 1:
        fail("direct command result lacks a single resource-wrapper command")
    prefix, scan = argv[:argv.index("--")], argv[argv.index("--") + 1:]
    if len(prefix) < 4 or Path(prefix[2]).name != "largefile_acceptance_resource_capture.py" or \
            not Path(prefix[2]).is_absolute() or Path(prefix[2]).is_symlink() or \
            prefix[3] != str(root) or len(scan) < 2 or \
            not Path(scan[0]).is_absolute() or Path(scan[0]).is_symlink() or \
            cases.sha256(Path(scan[0])) != scanner_hash or \
            scan[-1] != identity["input"]:
        fail("direct command did not run the bound scanner on the bound input")
    manifest_lines = file(root, "provenance/source-content.sha256").read_text(
        encoding="utf-8").splitlines()
    wrapper_hashes = [line.split("  ", 1)[0] for line in manifest_lines
                      if line.endswith("  tools/largefile_acceptance_resource_capture.py")]
    if len(wrapper_hashes) != 1 or wrapper_hashes[0] != cases.sha256(Path(prefix[2])):
        fail("direct resource wrapper is not bound to the source manifest")
    wrapper_options = {
        "--kind": "clamscan", "--id": "file", "--case-id": case_id,
        "--source-manifest": "provenance/source-content.sha256",
        "--build-identity": "provenance/clamscan",
        "--config": "provenance/CMakeCache.txt",
        "--temporary-root": "tmp",
        "--process-log": "provenance/scan.log",
        "--sample-log": "provenance/samples.tsv",
    }
    for option, expected in wrapper_options.items():
        if prefix.count(option) != 1 or prefix.index(option) + 1 >= len(prefix) or \
                prefix[prefix.index(option) + 1] != expected:
            fail(f"direct resource command lacks the bound {option}")
    scan_options = {
        "--database": str(root / "provenance/database.ndb"),
        "--report-json": str(root / "scan-report.jsonl"),
        "--tempdir": str(root / "tmp"),
        "--max-filesize": "32G", "--max-scansize": "64G",
        "--max-temporary-size": "64G",
    }
    if case_id != "clamscan:file:limit-edge":
        scan_options["--max-contiguous-size"] = "32G"
    for option, expected in scan_options.items():
        values = [arg.split("=", 1)[1] for arg in scan if arg.startswith(f"{option}=")]
        if values != [expected]:
            fail(f"direct scanner command lacks one bound {option}")
    alert_option = (
        "--alert-exceeds-max=no"
        if case_id == "clamscan:file:limit-edge"
        else "--alert-exceeds-max=yes"
    )
    for option in ("--log-hash", "--debug", "--no-summary", alert_option):
        if scan.count(option) != 1:
            fail(f"direct scanner command lacks one {option}")
    return command_result["exit_code"]


def produce(root: Path, manifest: Path, mapping_path: Path,
            sanitizer: str) -> Path:
    root = root.resolve()
    if sanitizer not in ("development", "release", "c-asan-ubsan", "rust-asan"):
        fail("direct case has an unsupported sanitizer label")
    if not root.is_dir() or root.is_symlink():
        fail("direct case evidence root is missing or symlinked")
    mapping = cases.validate_map(manifest, mapping_path)
    before = file(root, "provenance/direct-inputs-before.json").read_bytes()
    if before != file(root, "provenance/direct-inputs-after.json").read_bytes():
        fail("direct input identity changed during scan")
    inputs = cases.load_json_object(before.decode("utf-8"), "direct input identity")
    if type(inputs.get("version")) is not int or inputs["version"] != 1 or \
            not isinstance(inputs.get("inputs"), dict) or len(inputs["inputs"]) != 1:
        fail("direct input identity has an invalid schema")
    role, identity = next(iter(inputs["inputs"].items()))
    if not isinstance(identity, dict):
        fail("direct input identity is malformed")
    artifact_hashes = {name: cases.sha256(file(root, name)) for name in ARTIFACTS}
    oracle = json_file(root, "provenance/direct-oracle.json")
    case_id, completion, reason, offset_scope = validate_oracle(oracle, identity, artifact_hashes)
    if role != oracle["fixture_role"]:
        fail("direct input role differs from the oracle")
    required = next(row for row in mapping if (row["kind"], row["id"]) == ("clamscan", "file"))
    if case_id not in required["required_case_ids"].split(","):
        fail("direct case is not required by the reviewed case map")
    command_result = json_file(root, "provenance/direct-command-result.json")
    exit_code = validate_command(root, command_result, identity,
                                 artifact_hashes["provenance/direct-oracle.json"],
                                 case_id, artifact_hashes["provenance/clamscan"])
    if exit_code != oracle["exit_code"]:
        fail("direct scanner exit differs from the independent oracle")
    report = one_report(root)
    if report.get("completion") != completion or \
            (report.get("reason") not in (None, "", reason)):
        fail("direct report contradicts the oracle completion/reason")
    for field in NUMERIC_REPORT_FIELDS:
        if type(report.get(field)) is not int or report[field] < 0:
            fail(f"direct report lacks a valid {field}")
    if completion == "DETECTION_TERMINATED":
        if report.get("last_alert") != oracle["alert_signature"]:
            fail("direct report contradicts the exact detection signature")
        if offset_scope == "root-input" and \
                report.get("last_alert_offset") != oracle["alert_offset"]:
            fail("direct report contradicts the exact root-input detection offset")
        if offset_scope == "nested-member" and report.get("last_alert_offset") is not None:
            fail("direct report mislabels a nested-member offset as a root-input offset")
    temporary = root / "tmp"
    if not temporary.is_dir() or temporary.is_symlink() or any(temporary.iterdir()):
        fail("direct scanner temporary root is not clean")
    log = file(root, "provenance/scan.log").read_text(encoding="utf-8", errors="replace")
    if completion == "DETECTION_TERMINATED" and offset_scope == "nested-member":
        signature = oracle["alert_signature"]
        escaped = re.escape(signature)
        if not signature.endswith(".UNOFFICIAL"):
            escaped += r"(?:\.UNOFFICIAL)?"
        offset = str(oracle["alert_offset"])
        trace = rf"(?:^|[ \t])signature {escaped} matched at {offset}(?=[ \t\r\n]|$)"
        if re.search(trace, log) is None:
            fail("direct matcher log lacks the exact nested-member signature offset")
    if sanitizer not in ("development", "release") and any(marker in log for marker in (
        "ERROR: AddressSanitizer", "ERROR: LeakSanitizer", "runtime error:",
    )):
        fail("direct sanitizer scan emitted an error diagnostic")
    resource_path = file(root, resources.RESOURCE_PATH)
    resource_rows = resources.read_resources(resource_path)
    if len(resource_rows) != 1 or resource_rows[0]["case_id"] != case_id:
        fail("direct case lacks one matching measured-resource row")
    platform = f"{os.uname().sysname}-{os.uname().machine}"
    if resource_rows[0]["platform"] != platform:
        fail("direct measured-resource platform differs from runner")
    verdict = report.get("verdict")
    verdict_name = {0: "CLEAN", 1: "TRUSTED", 2: "DETECTED", 3: "MALWARE"}.get(verdict)
    if verdict_name is None:
        fail("direct report has an invalid verdict")
    row = {
        "kind": "clamscan", "id": "file", "case_id": case_id,
        "source_manifest_sha256": artifact_hashes["provenance/source-content.sha256"],
        "build_identity_sha256": artifact_hashes["provenance/clamscan"],
        "config_sha256": artifact_hashes["provenance/CMakeCache.txt"],
        "platform": platform, "fixture_role": role,
        "fixture_sha256": identity["sha256"],
        "oracle_sha256": artifact_hashes["provenance/direct-oracle.json"],
        "database_sha256": artifact_hashes["provenance/database.ndb"],
        "exit_code": str(exit_code), "verdict": verdict_name,
        "completion": completion, "reason": reason,
        "alert_signature": oracle["alert_signature"],
        "alert_offset": str(oracle["alert_offset"]) if completion == "DETECTION_TERMINATED" else "-",
        "alert_offset_scope": offset_scope,
        "alert_offset_source": (
            "structured-report" if offset_scope == "root-input" else
            "matcher-debug-log" if offset_scope == "nested-member" else "none"
        ),
        "alert_offset_evidence": (
            "scan-report.jsonl" if offset_scope == "root-input" else
            "provenance/scan.log" if offset_scope == "nested-member" else "-"
        ),
        **{field: str(report[field]) for field in NUMERIC_REPORT_FIELDS},
        "sanitizer": sanitizer,
        "resource_phase": "rss<=33554432;temporary<=68719476736",
        "health": "pass", "cleanup": "pass", "artifacts": ",".join(ARTIFACTS),
    }
    destination = root / "provenance/acceptance-cases.tsv"
    with destination.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerow(row)
    resources.bind(destination, root, resource_path)
    cases.validate_records(destination, mapping, evidence_root=root)
    resources.validate(destination, root, resource_path)
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_root", type=Path)
    parser.add_argument("--manifest", type=Path, default=Path("docs/largefile-capabilities.tsv"))
    parser.add_argument("--map", dest="mapping", type=Path,
                        default=Path("docs/largefile-capability-case-map.tsv"))
    parser.add_argument("--sanitizer", required=True,
                        choices=("development", "release", "c-asan-ubsan", "rust-asan"))
    args = parser.parse_args(argv)
    try:
        path = produce(args.evidence_root, args.manifest, args.mapping, args.sanitizer)
    except (ValueError, OSError, csv.Error) as error:
        print(f"direct-file case producer failed: {error}", file=sys.stderr)
        return 1
    print(f"direct-file case producer wrote one validated case: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
