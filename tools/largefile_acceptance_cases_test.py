#!/usr/bin/env python3
import csv
from pathlib import Path
import tempfile
import unittest

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
            "alert_offset": "7", "sanitizer": "release",
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
            "scan.log": "fixture: Test.Signature FOUND\n",
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
            "scan.log": "fixture: Test.Signature FOUND\n",
        }
        for name, content in artifact_names.items():
            (evidence / name).write_text(content, encoding="utf-8")
        fixture_hash = cases.sha256(evidence / "fixture.bin")
        (provenance / "service-inputs-before.json").write_text(
            '{"version": 1, "inputs": {"service-zip": {"sha256": "' +
            fixture_hash + '"}}}\n',
            encoding="utf-8",
        )

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
        with self.assertRaisesRegex(ValueError, "lacks a service fixture role"):
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
        (provenance / "service-inputs-before.json").write_text(
            '{"version": 1, "inputs": {"service-zip": {"sha256": "' +
            fixture_hash + '"}}}\n',
            encoding="utf-8",
        )
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
