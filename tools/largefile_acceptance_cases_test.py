#!/usr/bin/env python3
import csv
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import largefile_acceptance_cases as cases


class AcceptanceCaseTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="largefile-cases-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.manifest = self.root / "manifest.tsv"
        with self.manifest.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
            writer.writerow(cases.MANIFEST_HEADER)
            writer.writerow(["parser", "CL_TYPE_ZIP", "pending", "libclamav/unzip.c", "work"])
            writer.writerow(["matcher", "pcre", "pending", "libclamav/matcher-pcre.c", "work"])
            writer.writerow(["clamd", "SCAN", "bounded", "clamd/server.c", "work"])
            writer.writerow(["unsupported", "macos-first-release", "unsupported", "CMakeLists.txt", "work"])
        self.mapping = self.root / "map.tsv"
        cases.write_map(self.manifest, self.mapping)

    def test_reviewed_map_covers_every_capability(self):
        mapping = cases.validate_map(self.manifest, self.mapping)
        self.assertEqual(len(mapping), 4)
        self.assertIn("parser:CL_TYPE_ZIP:valid-complete", mapping[0]["required_case_ids"])
        self.assertIn("matcher:pcre:exact-tail", mapping[1]["required_case_ids"])
        self.assertIn("clamd:SCAN:clean-edge", mapping[2]["required_case_ids"])
        self.assertEqual(mapping[3]["required_case_ids"], "unsupported:macos-first-release:unsupported-policy")

    def test_on_access_permission_requires_fail_closed_cases(self):
        self.assertEqual(
            cases.case_suffixes("on-access", "permission"),
            [
                "clean-edge", "detection-edge", "limit-edge", "resource-edge",
                "timeout-edge", "parser-edge",
            ],
        )
        self.assertEqual(
            cases.case_completion_contract("on-access:permission:parser-edge"),
            {"MALFORMED_CONFIRMED"},
        )
        self.assertEqual(
            cases.case_completion_contract("on-access:permission:timeout-edge"),
            {"LIMIT_INCOMPLETE"},
        )

    def test_missing_capability_is_rejected(self):
        lines = self.mapping.read_text(encoding="utf-8").splitlines()
        self.mapping.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing capabilities"):
            cases.validate_map(self.manifest, self.mapping)

    def test_record_schema_accepts_empty_incomplete_file(self):
        records = self.root / "records.tsv"
        records.write_text("\t".join(cases.RECORD_HEADER) + "\n", encoding="utf-8")
        self.assertEqual(cases.validate_records(records, cases.validate_map(self.manifest, self.mapping)), 0)

    def test_record_schema_rejects_rows_with_wrong_column_count(self):
        records = self.root / "records.tsv"
        header = "\t".join(cases.RECORD_HEADER)
        valid_width = "\t".join("0" for _ in cases.RECORD_HEADER)
        for malformed in (valid_width + "\textra", "\t".join("0" for _ in cases.RECORD_HEADER[:-1])):
            records.write_text(f"{header}\n{malformed}\n", encoding="utf-8")
            with self.subTest(column_count=malformed.count("\t") + 1):
                with self.assertRaisesRegex(ValueError, "columns at line 2"):
                    cases.validate_records(records, cases.validate_map(self.manifest, self.mapping))

    def test_tsv_reader_rejects_malformed_quoting(self):
        malformed = self.root / "malformed.tsv"
        malformed.write_text(
            "\t".join(cases.RECORD_HEADER) + "\n\"unterminated\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "malformed TSV"):
            cases.read_tsv(malformed, cases.RECORD_HEADER)

    def test_structured_json_rejects_duplicate_keys(self):
        self.assertEqual(cases.load_json_object('{"status": 0}', "report"), {"status": 0})
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: status"):
            cases.load_json_object('{"status": 0, "status": 1}', "report")
        with self.assertRaisesRegex(ValueError, "not a JSON object"):
            cases.load_json_object("[]", "report")

    def test_service_fixture_rehash_rejects_path_replacement(self):
        fixture = self.root / "fixture.bin"
        fixture.write_bytes(b"fixture bytes\n")
        info = fixture.stat()
        identity = {
            "input": str(fixture), "size": info.st_size,
            "sha256": cases.sha256(fixture),
            "allocated_bytes": info.st_blocks * 512,
            "first_hole": None,
        }
        real_stat = os.stat
        nofollow_calls = 0

        def replaced_path(path, *args, **kwargs):
            nonlocal nofollow_calls
            result = real_stat(path, *args, **kwargs)
            if Path(path) == fixture and kwargs.get("follow_symlinks") is False:
                nofollow_calls += 1
                if nofollow_calls == 1:
                    return result
                fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_blocks")
                values = {field: getattr(result, field) for field in fields}
                values["st_ino"] += 1
                return SimpleNamespace(**values)
            return result

        with mock.patch.object(cases.os, "stat", side_effect=replaced_path):
            with self.assertRaisesRegex(ValueError, "changed during verification"):
                cases.verify_service_fixture(identity, identity["sha256"], "service-fixture")

    def test_direct_file_identity_binds_external_fixture_report_and_log(self):
        evidence = self.root / "direct-evidence"
        provenance = evidence / "provenance"
        provenance.mkdir(parents=True)
        fixture = self.root / "external-fixture.bin"
        fixture.write_bytes(b"direct-file-fixture\n")
        info = fixture.stat()
        fixture_hash = cases.sha256(fixture)
        identity = {
            "input": str(fixture), "size": info.st_size,
            "sha256": fixture_hash, "allocated_bytes": info.st_blocks * 512,
            "first_hole": None,
        }
        for name, content in {
            "source.txt": "source\n", "build.txt": "build\n",
            "config.txt": "config\n", "oracle.txt": "oracle\n",
            "database.txt": "database\n",
        }.items():
            (evidence / name).write_text(content, encoding="utf-8")
        report = {
            "version": 1, "target": str(fixture), "root_size": info.st_size,
            "status": 0, "verdict": 0, "completion": "COMPLETE",
            "logical_bytes": info.st_size, "matcher_bytes": info.st_size,
            "contiguous_bytes": 0, "temporary_bytes": 0,
            "files_scanned": 1, "max_recursion_depth": 0,
            "elapsed_ms": 1, "parser_operations": 1,
            "detector_operations": 1, "skipped_operations": 0,
        }
        report_path = evidence / "scan-report.jsonl"
        log_path = provenance / "scan.log"
        before_path = provenance / "direct-inputs-before.json"
        after_path = provenance / "direct-inputs-after.json"
        oracle_path = provenance / "direct-oracle.json"
        oracle = {
            "case_id": "clamscan:file:clean-edge", "alert_signature": "-",
            "alert_offset": None, "alert_offset_scope": "none",
        }

        def write_oracle():
            oracle_path.write_text(json.dumps(oracle) + "\n", encoding="utf-8")
            row["oracle_sha256"] = cases.sha256(oracle_path)

        def write_base():
            report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")
            log_path.write_text(
                f"{fixture} FileHash: {fixture_hash} (sha2-256)\n"
                f"{fixture}: OK\n", encoding="utf-8",
            )
            inputs = json.dumps({
                "version": 1, "inputs": {"direct-raw": identity},
            }, sort_keys=True) + "\n"
            before_path.write_text(inputs, encoding="utf-8")
            after_path.write_text(inputs, encoding="utf-8")
            write_oracle()

        row = {field: "0" for field in cases.RECORD_HEADER}
        row.update({
            "kind": "clamscan", "id": "file", "case_id": "clamscan:file:clean-edge",
            "source_manifest_sha256": cases.sha256(evidence / "source.txt"),
            "build_identity_sha256": cases.sha256(evidence / "build.txt"),
            "config_sha256": cases.sha256(evidence / "config.txt"),
            "platform": "Linux-x86_64", "fixture_role": "direct-raw",
            "fixture_sha256": fixture_hash,
            "oracle_sha256": "0" * 64,
            "database_sha256": cases.sha256(evidence / "database.txt"),
            "exit_code": "0", "verdict": "CLEAN", "completion": "COMPLETE",
            "reason": "complete", "alert_signature": "-", "alert_offset": "-",
            "alert_offset_scope": "none", "alert_offset_source": "none",
            "alert_offset_evidence": "-",
            "logical_bytes": str(info.st_size), "matcher_bytes": str(info.st_size),
            "contiguous_bytes": "0", "temporary_bytes": "0", "files_scanned": "1",
            "max_recursion_depth": "0", "elapsed_ms": "1", "parser_operations": "1",
            "detector_operations": "1", "skipped_operations": "0",
            "sanitizer": "development", "resource_phase": "rss<=33554432;temporary<=68719476736",
            "health": "pass", "cleanup": "pass",
            "artifacts": ",".join((
                "source.txt", "build.txt", "config.txt", "oracle.txt", "database.txt",
                "scan-report.jsonl", "provenance/scan.log",
                "provenance/direct-oracle.json",
                "provenance/direct-inputs-before.json", "provenance/direct-inputs-after.json",
            )),
        })
        records = evidence / "records.tsv"
        mapping = [{
            "kind": "clamscan", "id": "file",
            "required_case_ids": "clamscan:file:clean-edge",
        }]

        def verify():
            with records.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(
                    stream, fieldnames=cases.RECORD_HEADER,
                    delimiter="\t", lineterminator="\n",
                )
                writer.writeheader()
                writer.writerow(row)
            return cases.validate_records(records, mapping, evidence_root=evidence)

        write_base()
        self.assertEqual(verify(), 1)
        self.assertNotIn("external-fixture.bin", row["artifacts"])
        row["sanitizer"] = "release"
        with self.assertRaisesRegex(ValueError, "lacks the exact edge size"):
            verify()
        row["sanitizer"] = "development"

        after_path.unlink()
        with self.assertRaisesRegex(ValueError, "direct-inputs-after.json"):
            verify()
        write_base()
        after_path.write_text('{}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "changed during qualification"):
            verify()
        write_base()

        report["target"] = str(self.root / "other-input.bin")
        report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not bind its input/outcome"):
            verify()
        report["target"] = str(fixture)
        write_base()

        log_path.write_text(f"{fixture}: OK\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "lacks the exact input hash"):
            verify()
        write_base()

        fixture.write_bytes(b"Xirect-file-fixture\n")
        with self.assertRaisesRegex(ValueError, "content does not match"):
            verify()
        fixture.write_bytes(b"direct-file-fixture\n")
        write_base()

        identity["allocated_bytes"] += 512
        write_base()
        with self.assertRaisesRegex(ValueError, "allocation changed"):
            verify()
        identity["allocated_bytes"] -= 512
        write_base()
        self.assertEqual(verify(), 1)

        mapping[0]["required_case_ids"] = "clamscan:file:detection-edge"
        row.update({
            "case_id": "clamscan:file:detection-edge", "exit_code": "1",
            "verdict": "DETECTED", "completion": "DETECTION_TERMINATED",
            "reason": "exact late marker", "alert_signature": "Test.Direct.UNOFFICIAL",
            "alert_offset": "7",
            "alert_offset_scope": "root-input", "alert_offset_source": "structured-report",
            "alert_offset_evidence": "scan-report.jsonl",
        })
        oracle.update({
            "case_id": row["case_id"], "alert_signature": row["alert_signature"],
            "alert_offset": 7, "alert_offset_scope": "root-input",
        })
        write_oracle()
        report.update({
            "status": 1, "verdict": 2, "completion": "DETECTION_TERMINATED",
            "last_alert": "Test.Direct.UNOFFICIAL", "last_alert_offset": 7,
        })
        report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")
        log_path.write_text(
            f"{fixture} FileHash: {fixture_hash} (sha2-256)\n"
            f"{fixture}: Test.Direct.UNOFFICIAL FOUND\n", encoding="utf-8",
        )
        self.assertEqual(verify(), 1)
        report["last_alert_offset"] = 8
        report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "contradicts"):
            verify()

        mapping[0]["required_case_ids"] = "clamscan:file:limit-edge"
        row.update({
            "case_id": "clamscan:file:limit-edge", "exit_code": "2",
            "verdict": "INCOMPLETE", "completion": "LIMIT_INCOMPLETE",
            "reason": "Heuristics.Limits.Exceeded.MaxFileSize",
            "alert_signature": "-", "alert_offset": "-",
            "alert_offset_scope": "none", "alert_offset_source": "none",
            "alert_offset_evidence": "-",
            "logical_bytes": "0", "matcher_bytes": "0", "files_scanned": "0",
            "parser_operations": "0", "detector_operations": "0",
            "skipped_operations": "1",
        })
        report.update({
            "status": 24, "verdict": 0, "completion": "LIMIT_INCOMPLETE",
            "reason": row["reason"], "logical_bytes": 0, "matcher_bytes": 0,
            "files_scanned": 0, "parser_operations": 0,
            "detector_operations": 0, "skipped_operations": 1,
            "max_file_size": 32 * 1024 * 1024 * 1024,
        })
        report.pop("last_alert")
        report.pop("last_alert_offset")
        oracle.update({
            "case_id": row["case_id"], "alert_signature": "-",
            "alert_offset": None, "alert_offset_scope": "none",
        })
        write_oracle()
        report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")
        log_path.write_text(f"{fixture}: MaxFileSize exceeded\n", encoding="utf-8")
        self.assertEqual(verify(), 1)
        row["reason"] = "Heuristics.Limits.Exceeded.MaxScanSize"
        with self.assertRaisesRegex(ValueError, "unsupported limit reason"):
            verify()

    def test_record_outcome_and_case_binding_are_fail_closed(self):
        records = self.root / "records.tsv"
        row = {field: "0" for field in cases.RECORD_HEADER}
        row.update({
            "kind": "matcher", "id": "pcre", "case_id": "matcher:pcre:exact-tail",
            "source_manifest_sha256": "a" * 64, "build_identity_sha256": "b" * 64,
            "config_sha256": "c" * 64, "platform": "linux-x86_64", "fixture_role": "exact-tail",
            "fixture_sha256": "d" * 64, "oracle_sha256": "e" * 64, "database_sha256": "f" * 64,
            "exit_code": "1", "verdict": "DETECTED", "completion": "DETECTION_TERMINATED",
            "reason": "exact tail marker", "alert_signature": "Test.Signature", "alert_offset": "34359738304",
            "alert_offset_scope": "root-input", "alert_offset_source": "structured-report",
            "alert_offset_evidence": "logs/pcre.txt",
            "sanitizer": "release",
            "resource_phase": "rss<=33554432;pcre<=41943040;post-pcre<12582912;temporary<=68719476736",
            "health": "pass", "cleanup": "pass", "artifacts": "logs/pcre.txt",
        })
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER, delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        mapping = cases.validate_map(self.manifest, self.mapping)
        self.assertEqual(cases.validate_records(records, mapping), 1)
        with self.assertRaisesRegex(ValueError, "missing required cases"):
            cases.validate_records(records, mapping, ("matcher", "pcre"))
        row["resource_phase"] = "focused"
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        with self.assertRaisesRegex(ValueError, "structured resource phases"):
            cases.validate_records(records, mapping)
        row["resource_phase"] = (
            "rss<=33554432;pcre<=41943040;post-pcre<12582912;"
            "temporary<=68719476736"
        )
        row["alert_offset"] = "-"
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER, delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        with self.assertRaisesRegex(ValueError, "exact alert binding"):
            cases.validate_records(records, mapping)

        row["alert_offset"] = "7"
        row["resource_phase"] += ";unreviewed=1"
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        with self.assertRaisesRegex(ValueError, "invalid resource phase token"):
            cases.validate_records(records, mapping)

    def test_measured_resource_budgets_are_canonical_and_fail_closed(self):
        valid = (
            "rss<=33554432;pcre<=41943040;post-pcre<12582912;"
            "temporary<=68719476736"
        )
        self.assertEqual(
            cases.parse_resource_phases(valid, 2),
            {"rss", "pcre", "post-pcre", "temporary"},
        )
        for phase, token in (
            ("rss", "rss<=33554433"),
            ("pcre", "pcre<=41943041"),
            ("post-pcre", "post-pcre<=12582912"),
            ("temporary", "temporary<=68719476737"),
        ):
            with self.subTest(phase=phase):
                with self.assertRaisesRegex(ValueError, f"{phase} resource budget"):
                    cases.parse_resource_phases(token, 2)

        with self.assertRaisesRegex(ValueError, "invalid measured resource phase"):
            cases.parse_resource_phases("post-pcre<12582912M", 2)

    def test_case_suffix_rejects_contradictory_completion(self):
        records = self.root / "records.tsv"
        row = {field: "0" for field in cases.RECORD_HEADER}
        row.update({
            "kind": "parser", "id": "CL_TYPE_ZIP", "case_id": "parser:CL_TYPE_ZIP:late-detection",
            "source_manifest_sha256": "a" * 64, "build_identity_sha256": "b" * 64,
            "config_sha256": "c" * 64, "platform": "linux-x86_64", "fixture_role": "late",
            "fixture_sha256": "d" * 64, "oracle_sha256": "e" * 64, "database_sha256": "f" * 64,
            "exit_code": "0", "verdict": "CLEAN", "completion": "COMPLETE",
            "reason": "contradictory control", "alert_signature": "-", "alert_offset": "-",
            "alert_offset_scope": "none", "alert_offset_source": "none",
            "alert_offset_evidence": "-",
            "sanitizer": "release",
            "resource_phase": "rss<=33554432;pcre<=41943040;post-pcre<12582912;temporary<=68719476736",
            "health": "pass", "cleanup": "pass", "artifacts": "logs/scan.txt",
        })
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        mapping = cases.validate_map(self.manifest, self.mapping)
        with self.assertRaisesRegex(ValueError, "does not match its case contract"):
            cases.validate_records(records, mapping)

    def test_generic_complete_case_rejects_noncomplete_outcome(self):
        mapping = [{
            "kind": "library",
            "id": "generic-reader",
            "required_case_ids": "library:generic-reader:complete",
        }]
        records = self.root / "records.tsv"
        row = {field: "0" for field in cases.RECORD_HEADER}
        row.update({
            "kind": "library", "id": "generic-reader",
            "case_id": "library:generic-reader:complete",
            "source_manifest_sha256": "a" * 64, "build_identity_sha256": "b" * 64,
            "config_sha256": "c" * 64, "platform": "linux-x86_64", "fixture_role": "complete",
            "fixture_sha256": "d" * 64, "oracle_sha256": "e" * 64, "database_sha256": "f" * 64,
            "exit_code": "1", "verdict": "DETECTED", "completion": "DETECTION_TERMINATED",
            "reason": "contradictory generic completion", "alert_signature": "Test.Signature",
            "alert_offset": "7", "alert_offset_scope": "root-input",
            "alert_offset_source": "structured-report", "alert_offset_evidence": "logs/scan.txt",
            "sanitizer": "release",
            "resource_phase": "rss<=33554432;pcre<=41943040;post-pcre<12582912;temporary<=68719476736",
            "health": "pass", "cleanup": "pass", "artifacts": "logs/scan.txt",
        })
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        with self.assertRaisesRegex(ValueError, "does not match its case contract"):
            cases.validate_records(records, mapping)

    def test_all_generated_case_suffixes_have_completion_contracts(self):
        generated = set()
        for kind, identifier in (
            ("library", "generic-reader"), ("library", "path"),
            ("matcher", "pcre"), ("feature", "ENABLE_TESTS"),
            ("parser", "CL_TYPE_ZIP"), ("clamscan", "file"),
            ("clamd", "SCAN"), ("milter", "message"),
            ("on-access", "permission"), ("unsupported", "first-release"),
        ):
            generated.update(cases.case_suffixes(kind, identifier))
        for kind, identifier in cases.R09_REQUIRED_CAPABILITIES:
            generated.update(cases.case_suffixes(kind, identifier))
        missing = {
            suffix for suffix in generated
            if cases.case_completion_contract(f"test:test:{suffix}") is None
        }
        self.assertEqual(missing, set())

    def test_standalone_fixture_binding_requires_retained_artifact(self):
        records = self.root / "records.tsv"
        evidence = self.root / "evidence"
        evidence.mkdir()
        artifact_names = {
            "source.txt": "source\n",
            "build.txt": "build\n",
            "config.txt": "config\n",
            "fixture.bin": "fixture bytes\n",
            "oracle.txt": "oracle\n",
            "database.txt": "database\n",
            "scan.log": "fixture: Test.Signature FOUND\n"
                         "LibClamAV debug: cli_bm_scanbuff: signature Test.Signature matched at 7\n",
        }
        for name, content in artifact_names.items():
            (evidence / name).write_text(content, encoding="utf-8")

        row = {field: "0" for field in cases.RECORD_HEADER}
        row.update({
            "kind": "parser", "id": "CL_TYPE_ZIP", "case_id": "parser:CL_TYPE_ZIP:late-detection",
            "source_manifest_sha256": cases.sha256(evidence / "source.txt"),
            "build_identity_sha256": cases.sha256(evidence / "build.txt"),
            "config_sha256": cases.sha256(evidence / "config.txt"),
            "platform": "linux-x86_64", "fixture_role": "standalone-zip",
            "fixture_sha256": cases.sha256(evidence / "fixture.bin"),
            "oracle_sha256": cases.sha256(evidence / "oracle.txt"),
            "database_sha256": cases.sha256(evidence / "database.txt"),
            "exit_code": "1", "verdict": "DETECTED", "completion": "DETECTION_TERMINATED",
            "reason": "late marker", "alert_signature": "Test.Signature", "alert_offset": "7",
            "alert_offset_scope": "nested-member", "alert_offset_source": "matcher-debug-log",
            "alert_offset_evidence": "scan.log",
            "sanitizer": "release",
            "resource_phase": "rss<=33554432;pcre<=41943040;post-pcre<12582912;temporary<=68719476736",
            "health": "pass", "cleanup": "pass", "artifacts": ",".join(artifact_names),
        })
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        mapping = cases.validate_map(self.manifest, self.mapping)
        self.assertEqual(cases.validate_records(records, mapping, evidence_root=evidence), 1)

        (evidence / "scan-link.log").symlink_to(evidence / "scan.log")
        row["artifacts"] = row["artifacts"].replace("scan.log", "scan-link.log")
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        with self.assertRaisesRegex(ValueError, "is symlinked"):
            cases.validate_records(records, mapping, evidence_root=evidence)

        row["artifacts"] = row["artifacts"].replace("scan-link.log", "scan.log")
        row["fixture_sha256"] = "f" * 64
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        with self.assertRaisesRegex(ValueError, "not bound to a retained fixture artifact"):
            cases.validate_records(records, mapping, evidence_root=evidence)

        row["fixture_sha256"] = cases.sha256(evidence / "fixture.bin")
        row["fixture_role"] = "-"
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        with self.assertRaisesRegex(ValueError, "lacks a fixture role"):
            cases.validate_records(records, mapping, evidence_root=evidence)

    def test_service_fixture_binding_requires_retained_identity_evidence(self):
        records = self.root / "records.tsv"
        evidence = self.root / "evidence"
        provenance = evidence / "provenance"
        provenance.mkdir(parents=True)
        artifact_names = {
            "source.txt": "source\n",
            "build.txt": "build\n",
            "config.txt": "config\n",
            "fixture.bin": "fixture bytes\n",
            "oracle.txt": "oracle\n",
            "database.txt": "database\n",
            "scan.log": "fixture: Test.Signature FOUND\n"
                         "LibClamAV debug: cli_bm_scanbuff: signature Test.Signature matched at 7\n",
        }
        for name, content in artifact_names.items():
            (evidence / name).write_text(content, encoding="utf-8")
        fixture_hash = cases.sha256(evidence / "fixture.bin")
        fixture_identity = {
            "input": str((evidence / "fixture.bin").resolve()),
            "size": (evidence / "fixture.bin").stat().st_size,
            "sha256": fixture_hash,
            "allocated_bytes": (evidence / "fixture.bin").stat().st_blocks * 512,
            "first_hole": None,
        }
        identity_path = provenance / "service-inputs-before.json"
        after_identity_path = provenance / "service-inputs-after.json"

        def write_identity():
            content = json.dumps({"version": 1, "inputs": {"service-zip": fixture_identity}}) + "\n"
            identity_path.write_text(content, encoding="utf-8")
            after_identity_path.write_text(content, encoding="utf-8")

        write_identity()

        row = {field: "0" for field in cases.RECORD_HEADER}
        row.update({
            "kind": "parser", "id": "CL_TYPE_ZIP", "case_id": "parser:CL_TYPE_ZIP:late-detection",
            "source_manifest_sha256": cases.sha256(evidence / "source.txt"),
            "build_identity_sha256": cases.sha256(evidence / "build.txt"),
            "config_sha256": cases.sha256(evidence / "config.txt"),
            "platform": "linux-x86_64", "fixture_role": "service-zip",
            "fixture_sha256": fixture_hash,
            "oracle_sha256": cases.sha256(evidence / "oracle.txt"),
            "database_sha256": cases.sha256(evidence / "database.txt"),
            "exit_code": "1", "verdict": "DETECTED", "completion": "DETECTION_TERMINATED",
            "reason": "late marker", "alert_signature": "Test.Signature", "alert_offset": "7",
            "alert_offset_scope": "nested-member", "alert_offset_source": "matcher-debug-log",
            "alert_offset_evidence": "scan.log",
            "sanitizer": "release",
            "resource_phase": "rss<=33554432;pcre<=41943040;post-pcre<12582912;temporary<=68719476736",
            "health": "pass", "cleanup": "pass",
            "artifacts": ",".join(artifact_names),
        })
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        mapping = cases.validate_map(self.manifest, self.mapping)
        with self.assertRaisesRegex(ValueError, "does not retain service input identity evidence"):
            cases.validate_records(records, mapping, evidence_root=evidence)

        row["artifacts"] += ",provenance/service-inputs-before.json"
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        with self.assertRaisesRegex(ValueError, "does not retain service input after evidence"):
            cases.validate_records(records, mapping, evidence_root=evidence)

        row["artifacts"] += ",provenance/service-inputs-after.json"
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        self.assertEqual(cases.validate_records(records, mapping, evidence_root=evidence), 1)

        after_identity_path.write_text('{"version": 1, "inputs": {}}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "changed during qualification"):
            cases.validate_records(records, mapping, evidence_root=evidence)
        write_identity()

        (evidence / "fixture.bin").write_bytes(b"mutated bytes\n")
        with self.assertRaisesRegex(ValueError, "content does not match"):
            cases.validate_records(records, mapping, evidence_root=evidence)
        (evidence / "fixture.bin").write_bytes(b"fixture bytes\n")

        fixture_identity["input"] = str(evidence / "missing.bin")
        write_identity()
        with self.assertRaisesRegex(ValueError, "missing or not a file"):
            cases.validate_records(records, mapping, evidence_root=evidence)
        fixture_identity["input"] = str((evidence / "fixture.bin").resolve())
        write_identity()
        self.assertEqual(cases.validate_records(records, mapping, evidence_root=evidence), 1)

        fixture_identity["allocated_bytes"] += 512
        write_identity()
        with self.assertRaisesRegex(ValueError, "allocation changed"):
            cases.validate_records(records, mapping, evidence_root=evidence)
        fixture_identity["allocated_bytes"] -= 512
        write_identity()

        fixture_identity["size"] = 32 * 1024 * 1024 * 1024
        write_identity()
        with self.assertRaisesRegex(ValueError, "lacks materialized exact-edge evidence"):
            cases.validate_records(records, mapping, evidence_root=evidence)
        fixture_identity["size"] = (evidence / "fixture.bin").stat().st_size
        write_identity()

        link = evidence / "fixture-link.bin"
        link.symlink_to(evidence / "fixture.bin")
        fixture_identity["input"] = str(link)
        write_identity()
        with self.assertRaisesRegex(ValueError, "fixture is symlinked"):
            cases.validate_records(records, mapping, evidence_root=evidence)
        fixture_identity["input"] = str((evidence / "fixture.bin").resolve())
        write_identity()
        self.assertEqual(cases.validate_records(records, mapping, evidence_root=evidence), 1)

        lifecycle = provenance / "service-lifecycle-detection.tsv"
        lifecycle.write_text(
            "event\tresult\n"
            "ping_before_cases\tpass\n"
            "ping_after_cases\tpass\n"
            "pidfile_present_after_start\tyes\n"
            "daemon_running_before_stop\tyes\n"
            "daemon_exited_after_stop\tyes\n"
            "socket_absent_after_stop\tyes\n"
            "pidfile_absent_after_stop\tyes\n",
            encoding="utf-8",
        )
        row["resource_phase"] = (
            "rss<=33554432;pcre<=41943040;post-pcre<12582912;"
            "temporary<=68719476736;daemon-health=ping-before-and-after;"
            "cleanup=lifecycle-verified"
        )
        row["artifacts"] += ",provenance/service-lifecycle-detection.tsv"
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        self.assertEqual(cases.validate_records(records, mapping, evidence_root=evidence), 1)

        row["fixture_role"] = "-"
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        with self.assertRaisesRegex(ValueError, "lacks a fixture role"):
            cases.validate_records(records, mapping, evidence_root=evidence)
        row["fixture_role"] = "service-zip"
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)

        lifecycle.write_text(
            lifecycle.read_text(encoding="utf-8").replace(
                "socket_absent_after_stop\tyes", "socket_absent_after_stop\tno",
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "complete daemon lifecycle contract"):
            cases.validate_records(records, mapping, evidence_root=evidence)

        lifecycle.write_text(
            lifecycle.read_text(encoding="utf-8").replace(
                "socket_absent_after_stop\tno", "socket_absent_after_stop\tyes",
            ),
            encoding="utf-8",
        )

        row["artifacts"] = row["artifacts"].replace(
            ",provenance/service-inputs-before.json", "",
        )
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)
        (provenance / "service-inputs-before.json").unlink()
        with self.assertRaisesRegex(ValueError, "lacks service input identity evidence"):
            cases.validate_records(records, mapping, evidence_root=evidence)
        write_identity()
        row["artifacts"] += ",provenance/service-inputs-before.json"
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)

        (provenance / "service-inputs-before.json").write_text("[]\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "service input identity evidence is malformed"):
            cases.validate_records(records, mapping, evidence_root=evidence)

        (provenance / "service-inputs-before.json").write_text(
            '{"version": 1, "version": 1, "inputs": {"service-zip": {"sha256": "' +
            fixture_hash + '"}}}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: version"):
            cases.validate_records(records, mapping, evidence_root=evidence)

    def test_r09_focus_cases_can_be_required_as_one_binding_gate(self):
        manifest = self.root / "r09-manifest.tsv"
        with manifest.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
            writer.writerow(cases.MANIFEST_HEADER)
            for kind, identifier in cases.R09_REQUIRED_CAPABILITIES:
                writer.writerow([kind, identifier, "pending", "source.c", "R09"])
        cases.write_map(manifest, self.root / "r09-map.tsv")
        mapping = cases.validate_map(manifest, self.root / "r09-map.tsv")
        records = self.root / "r09-records.tsv"
        rows = []
        for kind, identifier in cases.R09_REQUIRED_CAPABILITIES:
            for suffix in ("required-behavior", "required-failure"):
                row = {field: "0" for field in cases.RECORD_HEADER}
                row.update({
                    "kind": kind,
                    "id": identifier,
                    "case_id": f"{kind}:{identifier}:{suffix}",
                    "source_manifest_sha256": "a" * 64,
                    "build_identity_sha256": "b" * 64,
                    "config_sha256": "c" * 64,
                    "platform": "linux-x86_64",
                    "fixture_role": "r09-focused",
                    "fixture_sha256": "d" * 64,
                    "oracle_sha256": "e" * 64,
                    "database_sha256": "f" * 64,
                    "alert_signature": "-",
                    "alert_offset": "-",
                    "alert_offset_scope": "none",
                    "alert_offset_source": "none",
                    "alert_offset_evidence": "-",
                    "reason": "focused R09 behavior result",
                    "sanitizer": "release",
                    "resource_phase": "rss<=33554432;pcre<=41943040;post-pcre<12582912;temporary<=68719476736",
                    "health": "pass",
                    "cleanup": "pass",
                    "artifacts": "logs/r09.txt",
                })
                if suffix == "required-failure":
                    row.update({
                        "exit_code": "2",
                        "verdict": "INCOMPLETE",
                        "completion": "UNSUPPORTED",
                        "reason": "required unsupported behavior",
                    })
                else:
                    row.update({
                        "exit_code": "0",
                        "verdict": "CLEAN",
                        "completion": "COMPLETE",
                    })
                rows.append(row)
        with records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        self.assertEqual(
            cases.validate_records(
                records, mapping,
                required_capabilities=cases.R09_REQUIRED_CAPABILITIES,
            ),
            len(rows),
        )
        self.assertEqual(
            cases.main([
                "--manifest", str(manifest), "--map", str(self.root / "r09-map.tsv"),
                "--records", str(records), "--check-records", "--require-r09",
            ]),
            0,
        )
        lines = records.read_text(encoding="utf-8").splitlines()
        records.write_text(
            "\n".join(
                line for line in lines
                if "parser:CL_TYPE_AI_MODEL:required-failure" not in line
            ) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "missing required cases"):
            cases.validate_records(
                records, mapping,
                required_capabilities=cases.R09_REQUIRED_CAPABILITIES,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
