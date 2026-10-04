#!/usr/bin/env python3
"""Fail-closed controls for combining independently captured case directories."""

import csv
import json
from pathlib import Path
import tempfile
import unittest

import largefile_acceptance_cases as cases
import largefile_acceptance_resources as resources
import largefile_case_bundle as bundle


class CaseRootsTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory(prefix="largefile-case-roots-")
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        (self.root / "provenance").mkdir()
        self.mapping = [{
            "kind": "parser", "id": "CL_TYPE_ZIP",
            "required_case_ids": (
                "parser:CL_TYPE_ZIP:valid-complete,"
                "parser:CL_TYPE_ZIP:late-detection"
            ),
        }]
        self.records = self.root / "provenance/acceptance-cases.tsv"
        self.roots = self.root / cases.CASE_ROOT_PATH
        self.rows = []
        for name, suffix in (("clean", "valid-complete"), ("detect", "late-detection")):
            case_root = self.root / "cases" / name
            (case_root / "provenance").mkdir(parents=True)
            artifacts = {
                "source.txt": "source\n", "build.txt": "build\n",
                "config.txt": "config\n", "fixture.bin": f"{name} fixture\n",
                "oracle.txt": f"{name} oracle\n", "database.txt": "database\n",
                "offset-report.jsonl": json.dumps({
                    "completion": "DETECTION_TERMINATED",
                    "last_alert": "Test.Marker", "last_alert_offset": 7,
                }) + "\n",
            }
            for path, content in artifacts.items():
                (case_root / path).write_text(content, encoding="utf-8")
            case_id = f"parser:CL_TYPE_ZIP:{suffix}"
            row = {field: "0" for field in cases.RECORD_HEADER}
            row.update({
                "kind": "parser", "id": "CL_TYPE_ZIP", "case_id": case_id,
                "source_manifest_sha256": cases.sha256(case_root / "source.txt"),
                "build_identity_sha256": cases.sha256(case_root / "build.txt"),
                "config_sha256": cases.sha256(case_root / "config.txt"),
                "platform": "Linux-x86_64", "fixture_role": name,
                "fixture_sha256": cases.sha256(case_root / "fixture.bin"),
                "oracle_sha256": cases.sha256(case_root / "oracle.txt"),
                "database_sha256": cases.sha256(case_root / "database.txt"),
                "exit_code": "0" if name == "clean" else "1",
                "verdict": "CLEAN" if name == "clean" else "DETECTED",
                "completion": "COMPLETE" if name == "clean" else "DETECTION_TERMINATED",
                "reason": "independent oracle", "alert_signature": "-" if name == "clean" else "Test.Marker",
                "alert_offset": "-" if name == "clean" else "7",
                "alert_offset_scope": "none" if name == "clean" else "root-input",
                "alert_offset_source": "none" if name == "clean" else "structured-report",
                "alert_offset_evidence": "-" if name == "clean" else "offset-report.jsonl",
                "sanitizer": "development", "health": "pass", "cleanup": "pass",
                "artifacts": ",".join((*artifacts, resources.RESOURCE_PATH)),
            })
            resource = {field: "0" for field in resources.RESOURCE_HEADER}
            resource.update({
                "kind": row["kind"], "id": row["id"], "case_id": case_id,
                "source_manifest_sha256": row["source_manifest_sha256"],
                "build_identity_sha256": row["build_identity_sha256"],
                "config_sha256": row["config_sha256"],
                "platform": "Linux-x86_64", "sample_source": "procfs-process-tree",
                "sample_count": "1", "rss_peak_kb": "100", "pss_peak_kb": "80",
                "vas_peak_kb": "200", "swap_peak_kb": "0",
                "temporary_peak_bytes": "0", "oom_events_peak": "0",
                "oom_kill_events_peak": "0", "oom_cgroup_count": "1",
                "oom_cgroup_digest": "1" * 64,
                "pcre_rss_peak_kb": "-", "post_pcre_rss_peak_kb": "-",
            })
            with (case_root / resources.RESOURCE_PATH).open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=resources.RESOURCE_HEADER,
                                        delimiter="\t", lineterminator="\n")
                writer.writeheader()
                writer.writerow(resource)
            row["resource_phase"] = (
                "rss<=33554432;temporary<=68719476736;resource-records=" +
                resources.sha256(case_root / resources.RESOURCE_PATH)
            )
            self.rows.append(row)
        self.write_records()
        self.write_roots((
            ("parser", "CL_TYPE_ZIP", "parser:CL_TYPE_ZIP:valid-complete", "cases/clean"),
            ("parser", "CL_TYPE_ZIP", "parser:CL_TYPE_ZIP:late-detection", "cases/detect"),
        ))

    def write_records(self):
        with self.records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows(self.rows)

    def write_roots(self, entries):
        with self.roots.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
            writer.writerow(cases.CASE_ROOT_HEADER)
            writer.writerows(entries)

    def verify(self):
        self.assertEqual(cases.validate_records(
            self.records, self.mapping, evidence_root=self.root,
            required_capability=("parser", "CL_TYPE_ZIP"),
        ), 2)

    def private_roots(self):
        result = []
        for name, row in zip(("clean", "detect"), self.rows):
            case_root = self.root / "cases" / name
            with (case_root / "provenance/acceptance-cases.tsv").open(
                "w", newline="", encoding="utf-8",
            ) as stream:
                writer = csv.DictWriter(stream, fieldnames=cases.RECORD_HEADER,
                                        delimiter="\t", lineterminator="\n")
                writer.writeheader()
                writer.writerow(row)
            result.append(case_root)
        return result
        self.assertEqual(resources.validate(
            self.records, self.root,
            required_capabilities=(("parser", "CL_TYPE_ZIP"),),
        ), 2)

    def test_two_case_roots_validate_with_separate_resource_hashes(self):
        self.verify()

    def test_map_must_cover_every_case(self):
        self.write_roots((
            ("parser", "CL_TYPE_ZIP", "parser:CL_TYPE_ZIP:valid-complete", "cases/clean"),
        ))
        with self.assertRaisesRegex(ValueError, "missing cases"):
            self.verify()

    def test_map_rejects_duplicate_and_escaped_roots(self):
        entries = (
            ("parser", "CL_TYPE_ZIP", "parser:CL_TYPE_ZIP:valid-complete", "cases/clean"),
            ("parser", "CL_TYPE_ZIP", "parser:CL_TYPE_ZIP:valid-complete", "cases/detect"),
        )
        self.write_roots(entries)
        with self.assertRaisesRegex(ValueError, "duplicates a case"):
            self.verify()
        self.write_roots((entries[0],
            ("parser", "CL_TYPE_ZIP", "parser:CL_TYPE_ZIP:late-detection", "../outside"),
        ))
        with self.assertRaisesRegex(ValueError, "unsafe directory"):
            self.verify()

    def test_map_rejects_symlinked_directory_and_manifest(self):
        (self.root / "cases/link").symlink_to(self.root / "cases/detect")
        self.write_roots((
            ("parser", "CL_TYPE_ZIP", "parser:CL_TYPE_ZIP:valid-complete", "cases/clean"),
            ("parser", "CL_TYPE_ZIP", "parser:CL_TYPE_ZIP:late-detection", "cases/link"),
        ))
        with self.assertRaisesRegex(ValueError, "symlinked"):
            self.verify()
        self.roots.unlink()
        self.roots.symlink_to(self.root / "cases/clean/source.txt")
        with self.assertRaisesRegex(ValueError, "map is symlinked"):
            self.verify()

    def test_swapped_case_directories_cannot_borrow_other_oracle(self):
        self.write_roots((
            ("parser", "CL_TYPE_ZIP", "parser:CL_TYPE_ZIP:valid-complete", "cases/detect"),
            ("parser", "CL_TYPE_ZIP", "parser:CL_TYPE_ZIP:late-detection", "cases/clean"),
        ))
        with self.assertRaisesRegex(ValueError, "fixture_sha256|oracle_sha256"):
            cases.validate_records(self.records, self.mapping, evidence_root=self.root)
        with self.assertRaisesRegex(ValueError, "does not cover its mapped cases"):
            resources.validate(self.records, self.root)

    def test_missing_case_private_sidecar_fails(self):
        (self.root / "cases/detect" / resources.RESOURCE_PATH).unlink()
        with self.assertRaisesRegex(ValueError, "missing or not a regular file"):
            resources.validate(self.records, self.root)

    def test_service_fixture_role_is_scoped_to_each_case_directory(self):
        for name, row in zip(("clean", "detect"), self.rows):
            case_root = self.root / "cases" / name
            fixture = case_root / "fixture.bin"
            info = fixture.stat()
            identity = {
                "input": str(fixture), "size": info.st_size,
                "sha256": row["fixture_sha256"],
                "allocated_bytes": info.st_blocks * 512,
                "first_hole": None,
            }
            content = json.dumps({
                "version": 1, "inputs": {"service-input": identity},
            }, sort_keys=True) + "\n"
            for suffix in ("before", "after"):
                relative = f"provenance/service-inputs-{suffix}.json"
                (case_root / relative).write_text(content, encoding="utf-8")
                row["artifacts"] += "," + relative
            row["fixture_role"] = "service-input"
        self.write_records()
        self.verify()

    def test_bundle_builder_copies_only_retained_case_artifacts(self):
        roots = self.private_roots()
        (roots[0] / "unlisted-large.bin").write_text("not an artifact\n", encoding="utf-8")
        result = bundle.assemble(self.root / "assembled", roots, self.mapping)
        self.assertEqual(result, self.root / "assembled")
        self.assertFalse((result / "cases/0001/unlisted-large.bin").exists())
        self.assertEqual(cases.validate_records(
            result / "provenance/acceptance-cases.tsv", self.mapping,
            evidence_root=result, required_capability=("parser", "CL_TYPE_ZIP"),
        ), 2)
        self.assertEqual(resources.validate(
            result / "provenance/acceptance-cases.tsv", result,
            required_capabilities=(("parser", "CL_TYPE_ZIP"),),
        ), 2)
        with self.assertRaisesRegex(ValueError, "already exists"):
            bundle.assemble(result, roots, self.mapping)

    def test_bundle_builder_rejects_oversized_artifact_without_output(self):
        roots = self.private_roots()
        with self.assertRaisesRegex(ValueError, "exceeds the copy limit"):
            bundle.assemble(self.root / "too-small-ceiling", roots, self.mapping,
                            max_artifact_bytes=10)
        self.assertFalse((self.root / "too-small-ceiling").exists())

    def test_bundle_builder_rejects_mixed_source_before_copying(self):
        self.rows[1]["source_manifest_sha256"] = "b" * 64
        roots = self.private_roots()
        with self.assertRaisesRegex(ValueError, "mixes source manifests"):
            bundle.assemble(self.root / "mixed-candidate", roots, self.mapping)
        self.assertFalse((self.root / "mixed-candidate").exists())

    def test_final_source_hash_rejects_a_mixed_candidate_bundle(self):
        final_source = self.rows[0]["source_manifest_sha256"]
        detect = self.root / "cases/detect"
        (detect / "source.txt").write_text("older candidate\n", encoding="utf-8")
        old_hash = cases.sha256(detect / "source.txt")
        self.rows[1]["source_manifest_sha256"] = old_hash
        sidecar = detect / resources.RESOURCE_PATH
        with sidecar.open(newline="", encoding="utf-8") as stream:
            resource = next(csv.DictReader(stream, delimiter="\t"))
        resource["source_manifest_sha256"] = old_hash
        with sidecar.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=resources.RESOURCE_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(resource)
        self.rows[1]["resource_phase"] = (
            "rss<=33554432;temporary<=68719476736;resource-records=" +
            resources.sha256(sidecar)
        )
        self.write_records()
        self.verify()
        with self.assertRaisesRegex(ValueError, "does not match the final candidate"):
            cases.validate_records(
                self.records, self.mapping, evidence_root=self.root,
                expected_source_sha256=final_source,
            )

    def test_sidecar_and_artifact_substitution_fail(self):
        self.verify()
        self.rows[1]["resource_phase"] = self.rows[0]["resource_phase"]
        self.write_records()
        with self.assertRaisesRegex(ValueError, "does not bind the resource-record hash"):
            resources.validate(self.records, self.root)
        self.rows[1]["resource_phase"] = (
            "rss<=33554432;temporary<=68719476736;resource-records=" +
            resources.sha256(self.root / "cases/detect" / resources.RESOURCE_PATH)
        )
        self.write_records()
        (self.root / "cases/detect/oracle.txt").write_text("substituted\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "oracle_sha256"):
            cases.validate_records(self.records, self.mapping, evidence_root=self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
