#!/usr/bin/env python3
"""Verify a PDF object-stream qualification evidence directory."""

import argparse
import csv
import hashlib
import json
import os
import pathlib
import re
import subprocess


CASES = {
    "raw": ("raw", "none", False, "detection"),
    "flate": ("flate", "none", False, "detection"),
    "filter-chain": ("asciihex-flate", "none", False, "detection"),
    "malformed": ("flate", "none", True, "detection"),
    "materialized": ("raw", "none", False, "detection"),
    "rc4-raw": ("raw", "rc4-r2", False, "detection"),
    "rc4-flate": ("flate", "rc4-r2", False, "detection"),
    "rc4-filter-chain": ("asciihex-flate", "rc4-r2", False, "detection"),
    "aesv2-raw": ("raw", "aesv2-r4", False, "detection"),
    "aesv2-flate": ("flate", "aesv2-r4", False, "detection"),
    "aesv2-filter-chain": ("asciihex-flate", "aesv2-r4", False, "detection"),
    "aesv3-raw": ("raw", "aesv3-r5", False, "detection"),
    "aesv3-flate": ("flate", "aesv3-r5", False, "detection"),
    "aesv3-filter-chain": ("asciihex-flate", "aesv3-r5", False, "detection"),
    "password-rc4": ("raw", "rc4-r2-password", False, "password"),
    "password-aesv2": ("raw", "aesv2-r4-password", False, "password"),
    "password-aesv3": ("raw", "aesv3-r5-password", False, "password"),
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SOURCE_ID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def fail(message):
    raise SystemExit(f"PDF object-stream evidence check failed: {message}")


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def integer(value, name, minimum=0, maximum=None):
    if not value.isascii() or not value.isdigit():
        fail(f"{name} is not a canonical non-negative integer")
    parsed = int(value)
    if parsed < minimum or (maximum is not None and parsed > maximum):
        fail(f"{name} is outside its accepted range")
    return parsed


def read_metadata(path):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            fail("metadata contains a malformed row")
        key, value = line.split("=", 1)
        if not key or key in values:
            fail("metadata contains an empty or duplicate key")
        values[key] = value
    return values


def read_tsv(path, expected_header):
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if reader.fieldnames != expected_header:
            fail(f"{path.name} has an unexpected schema")
        return list(reader)


def safe_evidence_path(root, relative):
    if pathlib.PurePosixPath(relative).is_absolute() or ".." in pathlib.PurePosixPath(relative).parts:
        fail("manifest path escapes the evidence directory")
    candidate = (root / pathlib.PurePosixPath(relative)).resolve()
    if os.path.commonpath((str(root.resolve()), str(candidate))) != str(root.resolve()):
        fail("manifest path resolves outside the evidence directory")
    return candidate


def require_hash(metadata, key, path):
    expected = metadata.get(key, "")
    if not SHA256.fullmatch(expected) or not path.is_file() or digest(path) != expected:
        fail(f"{key} does not bind {path.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence")
    parser.add_argument("--allow-dirty-source", action="store_true")
    args = parser.parse_args()

    evidence = pathlib.Path(args.evidence).resolve()
    source_root = pathlib.Path(__file__).resolve().parent.parent
    metadata_path = evidence / "evidence-metadata.txt"
    if not metadata_path.is_file():
        fail("evidence metadata is missing")
    metadata = read_metadata(metadata_path)
    expected_keys = {
        "schema_version", "source_revision_type", "source_commit", "source_tree",
        "source_tree_status", "source_manifest_sha256", "scanner_sha256",
        "scanner_type_sha256", "scanner_version_sha256", "ldd_sha256",
        "openssl_version_sha256",
        "runtime_dependencies_manifest_sha256", "database_manifest_sha256",
        "custom_signature_sha256", "generator_sha256",
        "qualification_sha256", "evidence_checker_sha256", "decoded_size",
        "generator_test_sha256",
        "rss_budget_kb", "temporary_budget_bytes", "max_scan_time_ms",
        "corpus_manifest_sha256", "results_sha256", "qualification_status",
    }
    if set(metadata) != expected_keys:
        fail("metadata keys do not match schema version 5")
    if metadata["schema_version"] != "5" or metadata["qualification_status"] != "pass":
        fail("metadata does not declare a schema-5 pass")
    if metadata["source_revision_type"] not in ("git-commit", "content-manifest"):
        fail("source revision type is invalid")
    if metadata["source_tree_status"] != "clean" and not args.allow_dirty_source:
        fail("release evidence is not bound to a clean source tree")
    for key in ("source_commit", "source_tree"):
        if not SOURCE_ID.fullmatch(metadata[key]):
            fail(f"{key} is not a supported source object identifier")
    for key in (
        "source_manifest_sha256", "scanner_sha256", "scanner_type_sha256",
        "scanner_version_sha256", "openssl_version_sha256", "ldd_sha256",
        "runtime_dependencies_manifest_sha256",
        "database_manifest_sha256", "custom_signature_sha256", "generator_sha256",
        "qualification_sha256", "evidence_checker_sha256", "corpus_manifest_sha256",
        "results_sha256", "generator_test_sha256",
    ):
        if not SHA256.fullmatch(metadata[key]):
            fail(f"{key} is not a SHA-256 digest")

    decoded_size = integer(metadata["decoded_size"], "decoded_size", 67108864, 4294967296)
    rss_budget = integer(metadata["rss_budget_kb"], "rss_budget_kb", 1, 41943040)
    temp_budget = integer(metadata["temporary_budget_bytes"], "temporary_budget_bytes")
    integer(metadata["max_scan_time_ms"], "max_scan_time_ms", 1, 4294967295)
    if temp_budget != 68719476736:
        fail("temporary budget is not the 64 GiB release value")

    require_hash(metadata, "source_manifest_sha256", evidence / "provenance/source-manifest.txt")
    require_hash(metadata, "scanner_sha256", evidence / "provenance/clamscan")
    require_hash(metadata, "scanner_type_sha256", evidence / "provenance/scanner-type.txt")
    require_hash(metadata, "scanner_version_sha256", evidence / "provenance/scanner-version.txt")
    require_hash(metadata, "openssl_version_sha256", evidence / "provenance/openssl-version.txt")
    require_hash(metadata, "ldd_sha256", evidence / "provenance/ldd-clamscan.txt")
    require_hash(
        metadata, "runtime_dependencies_manifest_sha256",
        evidence / "provenance/runtime-dependencies.tsv",
    )
    require_hash(metadata, "database_manifest_sha256", evidence / "provenance/database-manifest.tsv")
    require_hash(metadata, "custom_signature_sha256", evidence / "database/pdf-objstm.ndb")
    require_hash(metadata, "generator_sha256", source_root / "tools/largefile_pdf_objstm_fixture.py")
    require_hash(metadata, "qualification_sha256", source_root / "tools/largefile_pdf_objstm_qualification.sh")
    require_hash(metadata, "evidence_checker_sha256", pathlib.Path(__file__).resolve())
    require_hash(metadata, "corpus_manifest_sha256", evidence / "corpus-manifest.tsv")
    require_hash(metadata, "results_sha256", evidence / "results.tsv")
    require_hash(metadata, "generator_test_sha256", evidence / "generator-test.log")
    scanner_type = (evidence / "provenance/scanner-type.txt").read_text(encoding="utf-8")
    if not re.search(r"ELF 64-bit .* x86-64", scanner_type):
        fail("scanner type is not Linux x86-64 ELF")
    if "not found" in (evidence / "provenance/ldd-clamscan.txt").read_text(encoding="utf-8"):
        fail("scanner dependency capture contains an unresolved library")
    signature = (evidence / "database/pdf-objstm.ndb").read_text(encoding="ascii")
    expected_signature = "LargeFile.PDF.ObjStm.Tail:0:*:434c414d41562d5044462d4f424a53544d2d5441494c2d4d41524b4552\n"
    if signature.lower() != expected_signature.lower():
        fail("custom marker signature differs from its exact oracle")

    if metadata["source_revision_type"] == "git-commit" and (source_root / ".git").exists():
        current = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        if current != metadata["source_commit"]:
            fail("evidence source commit differs from the current checkout")

    database_rows = read_tsv(
        evidence / "provenance/database-manifest.tsv", ["path", "size", "sha256"]
    )
    if not database_rows:
        fail("database manifest is empty")
    database_paths = set()
    for row in database_rows:
        if not row["path"] or row["path"] in database_paths or any(ch in row["path"] for ch in "\t\r\n"):
            fail("database manifest contains an invalid path")
        database_paths.add(row["path"])
        integer(row["size"], "database file size")
        if not SHA256.fullmatch(row["sha256"]):
            fail("database manifest contains an invalid digest")

    dependency_rows = read_tsv(
        evidence / "provenance/runtime-dependencies.tsv",
        ["source", "artifact", "size", "sha256"],
    )
    if not dependency_rows:
        fail("runtime dependency manifest is empty")
    dependency_artifacts = set()
    for row in dependency_rows:
        if not row["source"].startswith("/") or any(ch in row["source"] for ch in "\t\r\n"):
            fail("runtime dependency source path is invalid")
        if row["artifact"] in dependency_artifacts:
            fail("runtime dependency artifact is duplicated")
        dependency_artifacts.add(row["artifact"])
        artifact = safe_evidence_path(evidence, row["artifact"])
        size = integer(row["size"], "runtime dependency size", 1)
        if not artifact.is_file() or artifact.stat().st_size != size:
            fail("runtime dependency artifact size differs from its manifest")
        if not SHA256.fullmatch(row["sha256"]) or digest(artifact) != row["sha256"]:
            fail("runtime dependency artifact hash differs from its manifest")

    corpus_rows = read_tsv(
        evidence / "corpus-manifest.tsv",
        ["case", "path", "filter", "encryption", "credential", "decoded_size", "encoded_size", "file_size", "sha256",
         "allocated_bytes", "metadata_sha256"],
    )
    if {row["case"] for row in corpus_rows} != set(CASES) or len(corpus_rows) != len(CASES):
        fail("corpus manifest does not contain exactly the required cases")
    for row in corpus_rows:
        expected_filter, expected_encryption, _, outcome = CASES[row["case"]]
        expected_credential = "nonempty" if outcome == "password" else "empty"
        if (
            row["filter"] != expected_filter
            or row["encryption"] != expected_encryption
            or row["credential"] != expected_credential
        ):
            fail(f"{row['case']} has the wrong filter, encryption, or credential oracle")
        path = safe_evidence_path(evidence, row["path"])
        size = integer(row["file_size"], f"{row['case']} file size", 1)
        allocated = integer(row["allocated_bytes"], f"{row['case']} allocation")
        integer(row["encoded_size"], f"{row['case']} encoded size", 1)
        case_decoded = integer(row["decoded_size"], f"{row['case']} decoded size", 1)
        if not path.is_file() or path.stat().st_size != size or digest(path) != row["sha256"]:
            fail(f"{row['case']} fixture size or hash differs from its oracle")
        fixture_metadata = evidence / "corpus" / f"{row['case']}.metadata"
        if (
            not SHA256.fullmatch(row["metadata_sha256"])
            or not fixture_metadata.is_file()
            or digest(fixture_metadata) != row["metadata_sha256"]
        ):
            fail(f"{row['case']} generator metadata differs from its oracle")
        metadata_values = {}
        for line in fixture_metadata.read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                fail(f"{row['case']} generator metadata contains a malformed row")
            key, value = line.split("=", 1)
            if key in metadata_values:
                fail(f"{row['case']} generator metadata contains a duplicate key")
            metadata_values[key] = value
        if metadata_values.get("encryption") != expected_encryption:
            fail(f"{row['case']} generator metadata has the wrong encryption oracle")
        if metadata_values.get("credential") != expected_credential:
            fail(f"{row['case']} generator metadata has the wrong credential oracle")
        encrypted_metadata = (
            re.fullmatch(r"[0-9a-f]{32}", metadata_values.get("file_id", ""))
            is not None
            and SHA256.fullmatch(metadata_values.get("file_key_sha256", ""))
            is not None
        )
        if encrypted_metadata != (expected_encryption != "none"):
            fail(f"{row['case']} generator security metadata oracle is incorrect")
        object_stream_iv = metadata_values.get("object_stream_iv")
        if expected_encryption.startswith(("aesv2-r4", "aesv3-r5")):
            if re.fullmatch(r"[0-9a-f]{32}", object_stream_iv or "") is None:
                fail(f"{row['case']} AES IV oracle is missing")
        elif expected_encryption.startswith("rc4-r2"):
            if object_stream_iv != "none":
                fail(f"{row['case']} RC4 IV oracle is incorrect")
        elif object_stream_iv is not None:
            fail(f"{row['case']} unencrypted metadata unexpectedly contains an IV")
        perms_sha256 = metadata_values.get("perms_sha256")
        if expected_encryption.startswith("aesv3-r5"):
            if not SHA256.fullmatch(perms_sha256 or ""):
                fail(f"{row['case']} AESV3 permissions oracle is missing")
        elif perms_sha256 is not None:
            fail(f"{row['case']} unexpectedly contains an AESV3 permissions oracle")
        if row["case"] == "materialized" and (case_decoded != decoded_size or allocated < size):
            fail("materialized fixture size/allocation does not meet its oracle")

    result_rows = read_tsv(
        evidence / "results.tsv",
        ["case", "status", "rss_kb", "temporary_peak_bytes", "minor_faults", "major_faults",
         "fs_inputs", "fs_outputs", "log_sha256", "report_sha256", "result"],
    )
    if {row["case"] for row in result_rows} != set(CASES) or len(result_rows) != len(CASES):
        fail("results do not contain exactly the required cases")
    for row in result_rows:
        _, encryption, malformed, outcome = CASES[row["case"]]
        expected_status = "1" if outcome == "detection" else "2"
        if row["status"] != expected_status or row["result"] != "pass":
            fail(f"{row['case']} does not have the exact status/pass result")
        if integer(row["rss_kb"], f"{row['case']} RSS", 1) > rss_budget:
            fail(f"{row['case']} exceeds the RSS budget")
        if integer(row["temporary_peak_bytes"], f"{row['case']} temporary peak") > temp_budget:
            fail(f"{row['case']} exceeds the temporary budget")
        for field in ("minor_faults", "major_faults", "fs_inputs", "fs_outputs"):
            integer(row[field], f"{row['case']} {field}")
        log = evidence / "logs" / f"{row['case']}.log"
        if not log.is_file() or not SHA256.fullmatch(row["log_sha256"]) or digest(log) != row["log_sha256"]:
            fail(f"{row['case']} log differs from its recorded digest")
        text = log.read_text(encoding="utf-8", errors="replace")
        required = ("pdf_extract_obj: Found /Type/ObjStm",)
        if outcome == "detection":
            required += (
                "LargeFile.PDF.ObjStm.Tail", "FOUND",
                "pdf_objstm_attach_file: retained ",
                "quota-accounted file-backed object stream",
                "pdf_find_and_parse_objs_in_objstm: Found object 5 0",
                "pdf_objstm_cleanup: releasing ",
            )
        else:
            required += (
                "encrypted PDF found, user password is NOT empty, cannot decrypt!",
                "pdf_find_and_extract_objs: encrypted pdf found, not decryptable",
                "PDF object-stream parsing did not complete",
            )
        if any(value not in text for value in required):
            fail(f"{row['case']} log is missing a required parser oracle")
        incomplete = "PDF object-stream parsing did not complete" in text
        if incomplete != (malformed or outcome == "password"):
            fail(f"{row['case']} malformed-status oracle is incorrect")
        has_bounded_rc4 = (
            "pdf_stream_decrypt_reader: decrypting RC4 stream in bounded windows" in text
        )
        has_bounded_aesv2 = (
            "pdf_stream_decrypt_reader: decrypting AESV2 stream in bounded CBC blocks" in text
        )
        has_bounded_aesv3 = (
            "pdf_stream_decrypt_reader: decrypting AESV3 stream in bounded CBC blocks" in text
        )
        has_empty_password = (
            "encrypted PDF found, user password is empty, will attempt to decrypt" in text
        )
        expected_diagnostics = {
            "none": (False, False, False, False),
            "rc4-r2": (True, False, False, True),
            "aesv2-r4": (False, True, False, True),
            "aesv3-r5": (False, False, True, True),
            "rc4-r2-password": (False, False, False, False),
            "aesv2-r4-password": (False, False, False, False),
            "aesv3-r5-password": (False, False, False, False),
        }[encryption]
        if (
            has_bounded_rc4,
            has_bounded_aesv2,
            has_bounded_aesv3,
            has_empty_password,
        ) != expected_diagnostics:
            fail(f"{row['case']} encrypted-stream diagnostic oracle is incorrect")
        if outcome == "password":
            forbidden = (
                "LargeFile.PDF.ObjStm.Tail", " FOUND", ": OK",
                "pdf_objstm_attach_file: retained ",
                "pdf_find_and_parse_objs_in_objstm: Found object 5 0",
            )
            if any(value in text for value in forbidden):
                fail(f"{row['case']} password-protected scan exposed a clean or plaintext result")

        report_path = evidence / "reports" / f"{row['case']}.jsonl"
        if (
            not report_path.is_file()
            or not SHA256.fullmatch(row["report_sha256"])
            or digest(report_path) != row["report_sha256"]
        ):
            fail(f"{row['case']} structured report differs from its recorded digest")
        report_lines = report_path.read_text(encoding="utf-8").splitlines()
        if len(report_lines) != 1:
            fail(f"{row['case']} structured report is not exactly one JSON object")
        duplicate = False

        def reject_duplicate_pairs(pairs):
            nonlocal duplicate
            value = {}
            for key, item in pairs:
                if key in value:
                    duplicate = True
                value[key] = item
            return value

        try:
            report = json.loads(report_lines[0], object_pairs_hook=reject_duplicate_pairs)
        except (TypeError, ValueError):
            fail(f"{row['case']} structured report is not valid JSON")
        if duplicate or not isinstance(report, dict) or report.get("version") != 1:
            fail(f"{row['case']} structured report has an invalid schema")
        if report.get("target") != str(safe_evidence_path(evidence, f"corpus/{row['case']}.pdf")):
            fail(f"{row['case']} structured report target is incorrect")
        if outcome == "detection":
            if (
                report.get("status") != 0
                or report.get("verdict") not in (2, 3)
                or report.get("completion") != "DETECTION_TERMINATED"
            ):
                fail(f"{row['case']} structured detection outcome is incorrect")
        else:
            reason = report.get("reason")
            if (
                not isinstance(report.get("status"), int)
                or report["status"] in (0, 1)
                or report.get("verdict") != 0
                or report.get("completion") != "UNSUPPORTED"
                or not isinstance(reason, str)
                or not reason
                or not isinstance(report.get("skipped_operations"), int)
                or report["skipped_operations"] < 1
            ):
                fail(f"{row['case']} structured password outcome is not fail-closed")
        tempdir = evidence / "tmp" / row["case"]
        if not tempdir.is_dir() or any(tempdir.iterdir()):
            fail(f"{row['case']} retained temporary residue")

    expected_corpus = {
        f"{case}.{suffix}" for case in CASES for suffix in ("pdf", "metadata")
    }
    if {path.name for path in (evidence / "corpus").iterdir()} != expected_corpus:
        fail("corpus directory contains unbound artifacts")
    if {path.name for path in (evidence / "logs").iterdir()} != {f"{case}.log" for case in CASES}:
        fail("log directory contains unbound artifacts")
    if {path.name for path in (evidence / "reports").iterdir()} != {f"{case}.jsonl" for case in CASES}:
        fail("structured report directory contains unbound artifacts")
    if {path.name for path in (evidence / "database").iterdir()} != {"pdf-objstm.ndb"}:
        fail("custom database directory contains unbound artifacts")
    if {path.name for path in (evidence / "tmp").iterdir()} != set(CASES):
        fail("temporary root contains an unexpected case directory")
    expected_provenance = {
        "clamscan",
        "database-manifest.tsv",
        "ldd-clamscan.txt",
        "openssl-version.txt",
        "runtime-components",
        "runtime-dependencies.tsv",
        "scanner-type.txt",
        "scanner-version.txt",
        "source-manifest.txt",
    }
    if {path.name for path in (evidence / "provenance").iterdir()} != expected_provenance:
        fail("provenance directory contains unbound artifacts")
    actual_components = {
        path.relative_to(evidence).as_posix()
        for path in (evidence / "provenance/runtime-components").iterdir()
    }
    if actual_components != dependency_artifacts:
        fail("runtime component directory contains unbound artifacts")

    print("PDF object-stream evidence check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
