#!/usr/bin/env python3
"""Regression tests for the fail-closed, two-run PCRE phase proof."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
import largefile_pcre_phase_evidence as checker
import largefile_acceptance_resources as resources

REAL_SIZE = checker.EXACT_SIZE_BYTES
SIZE = 128
PREFIX = (
    f"largefile_pcre_phase: phase=before-pcre object_id=7 recursion_level=0 subject_bytes={SIZE} subject_released=0\n"
    f"largefile_pcre_phase: phase=pcre object_id=7 recursion_level=0 subject_bytes={SIZE} subject_released=0\n"
    f"largefile_pcre_phase: phase=post-pcre-before-deep-parse object_id=7 recursion_level=0 subject_bytes={SIZE} subject_released=1\n"
)
DEEP = "largefile_pcre_phase: phase=deep-parse object_id=7 recursion_level=0 subject_released=1\n"
MATCH = f"LibClamAV debug: cli_pcre_scanbuf: located regex match @ {SIZE - 64}\n"


class PcrePhaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        size_patch = mock.patch.object(checker, "EXACT_SIZE_BYTES", SIZE)
        size_patch.start()
        self.addCleanup(size_patch.stop)
        self.work = tempfile.TemporaryDirectory(prefix="clamav-pcre-phase-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        (self.root / "provenance").mkdir()
        (self.root / "artifacts").mkdir()
        (self.root / "provenance/source-manifest.txt").write_text("source\n", encoding="utf-8")
        source_hash = checker.digest(self.root / "provenance/source-manifest.txt")
        (self.root / "provenance/build-identity.txt").write_text(
            f"CLAMAV_SOURCE_COMMIT:INTERNAL={source_hash}\n"
            f"CLAMAV_SOURCE_MANIFEST_SHA256:INTERNAL={source_hash}\n",
            encoding="utf-8")
        (self.root / "artifacts/fixture.bin").write_bytes(b"fixture\n" * 16)
        (self.root / "artifacts/scanner.bin").write_bytes(b"scanner\n")
        self.samples = {}
        for run in ("detection", "continuation"):
            phases = checker.DETECTION_PHASES if run == "detection" else checker.CONTINUATION_PHASES
            pid = 101 if run == "detection" else 201
            time_base = 0 if run == "detection" else 1000
            self.samples[run] = [
                {"sequence": index, "timestamp_ns": index * 100, "phase": phase,
                 "rss_kb": rss, "tree_rss_kb": tree, "process_count": 2,
                 "root_pid": pid, "sampled_pids": f"{pid},{pid + 1}"}
                for index, (phase, rss, tree) in enumerate(zip(
                    phases, (1024, 30000000, 8000000, 7000000),
                    (2048, 40000000, 11999999, 11000000)), 1)
            ]
            for sample in self.samples[run]:
                sample["timestamp_ns"] += time_base
            self.artifact(run, "database").write_text(f"database-{run}\n", encoding="utf-8")
            self.write_samples(run)
            self.artifact(run, "process-log").write_text(
                PREFIX + (DEEP if run == "continuation" else MATCH), encoding="utf-8")
            self.artifact(run, "phase-events").write_text(
                "pcre-start\npost-pcre\n" +
                ("deep-parse\n" if run == "continuation" else "") +
                "complete\n", encoding="utf-8")
            config = {
                "case_id": "matcher:pcre:full-subject-" +
                           ("tail" if run == "detection" else "release"),
                "source_manifest_sha256": checker.digest(
                    self.root / "provenance/source-manifest.txt"),
                "build_identity_sha256": checker.digest(
                    self.root / "provenance/build-identity.txt"),
                "scanner": str(self.root / "artifacts/scanner.bin"),
                "scanner_sha256": checker.digest(self.root / "artifacts/scanner.bin"),
                "database": str(self.artifact(run, "database")),
                "database_sha256": checker.digest(self.artifact(run, "database")),
                "fixture": str(self.root / "artifacts/fixture.bin"),
                "fixture_sha256": checker.digest(self.root / "artifacts/fixture.bin"),
            }
            config["args"] = [f"--database={config['database']}", "--debug", "--allmatch",
                              "--max-filesize=32G", "--max-contiguous-size=32G",
                              "--pcre-max-filesize=32G", config["fixture"]]
            self.artifact(run, "config").write_text(json.dumps(config), encoding="utf-8")
            sample_peaks = self.sample_peaks(run)
            row = {field: "0" for field in resources.RESOURCE_HEADER}
            row.update({
                "kind": "matcher", "id": "pcre",
                "case_id": "full-subject-" + ("tail" if run == "detection" else "release"),
                "source_manifest_sha256": config["source_manifest_sha256"],
                "build_identity_sha256": config["build_identity_sha256"],
                "config_sha256": checker.digest(self.artifact(run, "config")),
                "platform": "Linux-x86_64", "sample_source": "procfs-process-tree",
                "sample_count": str(len(self.samples[run])),
                "rss_peak_kb": str(sample_peaks["rss_peak_kb"]),
                "pss_peak_kb": "1000", "vas_peak_kb": "50000000",
                "oom_cgroup_count": "1", "oom_cgroup_digest": "0" * 64,
                "pcre_rss_peak_kb": str(sample_peaks["pcre_rss_peak_kb"]),
                "post_pcre_rss_peak_kb": str(sample_peaks["post_pcre_rss_peak_kb"]),
            })
            self.artifact(run, "resource-row").write_text(
                "\t".join(resources.RESOURCE_HEADER) + "\n" +
                "\t".join(row[field] for field in resources.RESOURCE_HEADER) + "\n",
                encoding="utf-8")
        self.artifact("detection", "scan-report").write_text(json.dumps({
            "completion": "DETECTION_TERMINATED", "root_size": SIZE,
            "contiguous_bytes": SIZE, "last_alert": "LargeFile.PCRE.Tail.UNOFFICIAL",
            "target": str(self.root / "artifacts/fixture.bin"),
            "status": 0, "verdict": 2, "skipped_operations": 0,
        }) + "\n", encoding="utf-8")
        self.artifact("continuation", "scan-report").write_text(json.dumps({
            "completion": "COMPLETE", "root_size": SIZE, "contiguous_bytes": SIZE,
            "status": 0, "verdict": 0, "skipped_operations": 0,
            "target": str(self.root / "artifacts/fixture.bin")}) + "\n", encoding="utf-8")

    def write_samples(self, run):
        self.artifact(run, "rss-samples").write_text(
            "\t".join(checker.SAMPLE_HEADER) + "\n" +
            "".join("\t".join(str(sample[field]) for field in checker.SAMPLE_HEADER) + "\n"
                    for sample in self.samples[run]), encoding="utf-8")

    def sample_peaks(self, run):
        samples = self.samples[run]
        return {
            "rss_peak_kb": max(sample["tree_rss_kb"] for sample in samples),
            "pcre_rss_peak_kb": max(sample["tree_rss_kb"] for sample in samples
                                    if sample["phase"] == "pcre"),
            "post_pcre_rss_peak_kb": max(sample["tree_rss_kb"] for sample in samples
                                         if sample["phase"] == "post-pcre-before-deep-parse"),
        }

    def artifact(self, run, role):
        return self.root / "artifacts" / f"{run}-{role}.txt"

    def document(self):
        identity = {
            field: {"path": f"provenance/{filename}",
                    "sha256": checker.digest(self.root / "provenance" / filename)}
            for field, filename in (
                ("source_manifest", "source-manifest.txt"),
                ("build_identity", "build-identity.txt"))
        }
        artifacts = [{"role": role, "path": f"artifacts/{name}",
                      "sha256": checker.digest(self.root / "artifacts" / name)}
                     for role, name in (("fixture", "fixture.bin"),
                                        ("scanner-binary", "scanner.bin"))]
        for run in ("detection", "continuation"):
            for role in ("config", "database", "rss-samples", "scan-report",
                         "process-log", "resource-row", "phase-events"):
                path = self.artifact(run, role)
                artifacts.append({"role": f"{run}-{role}", "path": f"artifacts/{path.name}",
                                  "sha256": checker.digest(path)})
        return {
            "proof_format_version": 2, "evidence_type": "pcre-rss-phases",
            "qualification_result": "pass", "capability_kind": "matcher",
            "capability_id": "pcre", "source_manifest_sha256": identity["source_manifest"]["sha256"],
            "platform": "Linux-x86_64",
            "budgets": {"pcre_rss_budget_kb": checker.PCRE_RSS_BUDGET_KB,
                        "post_pcre_rss_budget_kb": checker.POST_PCRE_RSS_BUDGET_KB},
            "identity": identity,
            "subject": {"case_id": "matcher:pcre:full-subject-tail",
                        "fixture_sha256": artifacts[0]["sha256"],
                        "expected_signature": "LargeFile.PCRE.Tail.UNOFFICIAL",
                        "detected_signature": "LargeFile.PCRE.Tail.UNOFFICIAL",
                        "expected_offset": SIZE - 64, "detected_offset": SIZE - 64,
                        "completion": "DETECTION_TERMINATED", "exit_code": 1},
            "continuation": {"case_id": "matcher:pcre:full-subject-release",
                             "fixture_sha256": artifacts[0]["sha256"],
                             "completion": "COMPLETE", "exit_code": 0},
            "transition": {"subject_released": True,
                           "deep_parse_started_after_release": True,
                           "phase_markers_are_runtime_events": True},
            "artifacts": artifacts,
        }

    def write(self, document=None):
        path = self.root / "provenance/pcre-rss-phase-evidence.json"
        path.write_text(json.dumps(self.document() if document is None else document),
                        encoding="utf-8")
        return path

    def bind_artifact(self, document, run, role):
        target = f"{run}-{role}"
        next(item for item in document["artifacts"] if item["role"] == target)["sha256"] = (
            checker.digest(self.artifact(run, role)))

    def test_valid_complete_contract(self):
        self.assertEqual(REAL_SIZE, 32 * 1024**3)
        checker.validate(self.write(), self.root)

    def test_raw_debug_prefix_is_accepted(self):
        doc = self.document()
        self.artifact("detection", "process-log").write_text(
            "".join("LibClamAV debug: " + line + "\n" for line in PREFIX.splitlines()) + MATCH,
            encoding="utf-8")
        self.bind_artifact(doc, "detection", "process-log")
        checker.validate(self.write(doc), self.root)

    def test_sparse_fixture_is_rejected(self):
        fixture = self.root / "artifacts/fixture.bin"
        with fixture.open("wb") as stream:
            stream.truncate(SIZE)
        doc = self.document()
        doc["subject"]["fixture_sha256"] = doc["artifacts"][0]["sha256"]
        doc["continuation"]["fixture_sha256"] = doc["artifacts"][0]["sha256"]
        with self.assertRaisesRegex(ValueError, "not fully allocated"):
            checker.validate(self.write(doc), self.root)

    def test_missing_phase_is_rejected(self):
        doc = self.document()
        self.samples["continuation"].pop(2)
        self.samples["continuation"][2]["sequence"] = 3
        self.write_samples("continuation")
        self.bind_artifact(doc, "continuation", "rss-samples")
        with self.assertRaisesRegex(ValueError, "do not cover"):
            checker.validate(self.write(doc), self.root)

    def test_pcre_ceiling_is_enforced(self):
        doc = self.document()
        self.samples["detection"][1]["tree_rss_kb"] = checker.PCRE_RSS_BUDGET_KB + 1
        self.write_samples("detection")
        self.bind_artifact(doc, "detection", "rss-samples")
        with self.assertRaisesRegex(ValueError, "40 GiB budget"):
            checker.validate(self.write(doc), self.root)

    def test_post_pcre_headroom_is_enforced(self):
        doc = self.document()
        self.samples["continuation"][2]["tree_rss_kb"] = checker.POST_PCRE_RSS_BUDGET_KB
        self.write_samples("continuation")
        self.bind_artifact(doc, "continuation", "rss-samples")
        with self.assertRaisesRegex(ValueError, "12 GiB budget"):
            checker.validate(self.write(doc), self.root)

    def test_out_of_order_samples_are_rejected(self):
        doc = self.document()
        self.samples["continuation"][1]["timestamp_ns"] = 99
        self.write_samples("continuation")
        self.bind_artifact(doc, "continuation", "rss-samples")
        with self.assertRaisesRegex(ValueError, "timestamps"):
            checker.validate(self.write(doc), self.root)

    def test_sample_phase_regression_is_rejected(self):
        doc = self.document()
        self.samples["continuation"][2]["phase"] = "before-pcre"
        self.write_samples("continuation")
        self.bind_artifact(doc, "continuation", "rss-samples")
        with self.assertRaisesRegex(ValueError, "phases are out of order"):
            checker.validate(self.write(doc), self.root)

    def test_exact_tail_proof_is_required(self):
        doc = self.document()
        doc["subject"]["detected_offset"] += 1
        with self.assertRaisesRegex(ValueError, "exact expected offset"):
            checker.validate(self.write(doc), self.root)

    def test_subject_release_transition_is_required(self):
        doc = self.document()
        doc["transition"]["subject_released"] = False
        with self.assertRaisesRegex(ValueError, "full-subject release"):
            checker.validate(self.write(doc), self.root)

    def test_missing_continuation_is_rejected(self):
        doc = self.document()
        del doc["continuation"]
        with self.assertRaisesRegex(ValueError, "continuation proof"):
            checker.validate(self.write(doc), self.root)

    def test_same_database_is_rejected(self):
        doc = self.document()
        self.artifact("continuation", "database").write_bytes(
            self.artifact("detection", "database").read_bytes())
        self.bind_artifact(doc, "continuation", "database")
        with self.assertRaisesRegex(ValueError, "databases must be distinct"):
            checker.validate(self.write(doc), self.root)

    def test_runtime_marker_is_required(self):
        doc = self.document()
        self.artifact("continuation", "process-log").write_text(
            PREFIX[:PREFIX.index("phase=pcre")], encoding="utf-8")
        self.bind_artifact(doc, "continuation", "process-log")
        with self.assertRaisesRegex(ValueError, "runtime marker"):
            checker.validate(self.write(doc), self.root)

    def test_runtime_marker_order_is_required(self):
        doc = self.document()
        self.artifact("continuation", "process-log").write_text(DEEP + PREFIX, encoding="utf-8")
        self.bind_artifact(doc, "continuation", "process-log")
        with self.assertRaisesRegex(ValueError, "out of order"):
            checker.validate(self.write(doc), self.root)

    def test_unrelated_object_cannot_supply_deep_parse(self):
        doc = self.document()
        self.artifact("continuation", "process-log").write_text(
            PREFIX + DEEP.replace("object_id=7", "object_id=3"), encoding="utf-8")
        self.bind_artifact(doc, "continuation", "process-log")
        with self.assertRaisesRegex(ValueError, "runtime marker"):
            checker.validate(self.write(doc), self.root)

    def test_detection_deep_marker_cannot_replace_continuation(self):
        doc = self.document()
        self.artifact("detection", "process-log").write_text(PREFIX + MATCH + DEEP, encoding="utf-8")
        self.bind_artifact(doc, "detection", "process-log")
        self.artifact("continuation", "process-log").write_text(PREFIX, encoding="utf-8")
        self.bind_artifact(doc, "continuation", "process-log")
        with self.assertRaisesRegex(ValueError, "runtime marker"):
            checker.validate(self.write(doc), self.root)

    def test_detection_may_emit_deep_marker_after_allmatch(self):
        doc = self.document()
        self.artifact("detection", "process-log").write_text(PREFIX + MATCH + DEEP, encoding="utf-8")
        self.bind_artifact(doc, "detection", "process-log")
        checker.validate(self.write(doc), self.root)

    def test_missing_object_identity_is_rejected(self):
        doc = self.document()
        self.artifact("continuation", "process-log").write_text(
            (PREFIX + DEEP).replace("object_id=7 ", ""), encoding="utf-8")
        self.bind_artifact(doc, "continuation", "process-log")
        with self.assertRaisesRegex(ValueError, "object-bound"):
            checker.validate(self.write(doc), self.root)

    def test_fixture_hash_mismatch_is_rejected(self):
        doc = self.document()
        doc["subject"]["fixture_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "retained fixture"):
            checker.validate(self.write(doc), self.root)

    def test_scan_report_mismatch_is_rejected(self):
        doc = self.document()
        self.artifact("detection", "scan-report").write_text(json.dumps({
            "completion": "DETECTION_TERMINATED", "root_size": SIZE,
            "contiguous_bytes": SIZE, "last_alert": "Wrong.UNOFFICIAL",
            "target": str(self.root / "artifacts/fixture.bin"),
            "status": 0, "verdict": 2, "skipped_operations": 0}) + "\n", encoding="utf-8")
        self.bind_artifact(doc, "detection", "scan-report")
        with self.assertRaisesRegex(ValueError, "exact expected alert"):
            checker.validate(self.write(doc), self.root)

    def test_match_offset_mismatch_is_rejected(self):
        doc = self.document()
        self.artifact("detection", "process-log").write_text(
            PREFIX + MATCH.replace(str(SIZE - 64), str(SIZE - 65)), encoding="utf-8")
        self.bind_artifact(doc, "detection", "process-log")
        with self.assertRaisesRegex(ValueError, "exact-tail regex match offset"):
            checker.validate(self.write(doc), self.root)

    def test_retained_samples_mismatch_is_rejected(self):
        doc = self.document()
        self.samples["continuation"][1]["tree_rss_kb"] -= 1
        self.write_samples("continuation")
        self.bind_artifact(doc, "continuation", "rss-samples")
        with self.assertRaisesRegex(ValueError, "differs from raw RSS trace"):
            checker.validate(self.write(doc), self.root)

    def test_sample_pid_set_must_include_root(self):
        doc = self.document()
        self.samples["continuation"][1]["sampled_pids"] = "202,203"
        self.write_samples("continuation")
        self.bind_artifact(doc, "continuation", "rss-samples")
        with self.assertRaisesRegex(ValueError, "PID trace is inconsistent"):
            checker.validate(self.write(doc), self.root)

    def test_sample_root_must_be_stable(self):
        doc = self.document()
        self.samples["continuation"][1]["root_pid"] = 202
        self.write_samples("continuation")
        self.bind_artifact(doc, "continuation", "rss-samples")
        with self.assertRaisesRegex(ValueError, "root PID changes"):
            checker.validate(self.write(doc), self.root)

    def test_resource_sample_count_must_match_raw_trace(self):
        doc = self.document()
        sidecar = self.artifact("continuation", "resource-row")
        sidecar.write_text(sidecar.read_text(encoding="utf-8").replace(
            "\t4\t", "\t5\t", 1), encoding="utf-8")
        self.bind_artifact(doc, "continuation", "resource-row")
        with self.assertRaisesRegex(ValueError, "sample_count differs"):
            checker.validate(self.write(doc), self.root)

    def test_phase_rendezvous_must_order_deep_parse(self):
        doc = self.document()
        self.artifact("continuation", "phase-events").write_text(
            "pcre-start\ndeep-parse\npost-pcre\ncomplete\n", encoding="utf-8")
        self.bind_artifact(doc, "continuation", "phase-events")
        with self.assertRaisesRegex(ValueError, "rendezvous is missing or out of order"):
            checker.validate(self.write(doc), self.root)

    def test_scanner_binary_must_match_config(self):
        doc = self.document()
        (self.root / "artifacts/scanner.bin").write_bytes(b"different-scanner\n")
        doc["artifacts"][1]["sha256"] = checker.digest(self.root / "artifacts/scanner.bin")
        with self.assertRaisesRegex(ValueError, "does not bind scanner"):
            checker.validate(self.write(doc), self.root)

    def test_build_cache_must_bind_manifest_identity(self):
        doc = self.document()
        build = self.root / "provenance/build-identity.txt"
        build.write_text(build.read_text(encoding="utf-8").replace(
            doc["source_manifest_sha256"], "0" * 64, 1), encoding="utf-8")
        doc["identity"]["build_identity"]["sha256"] = checker.digest(build)
        with self.assertRaisesRegex(ValueError, "does not bind CLAMAV_SOURCE_COMMIT"):
            checker.validate(self.write(doc), self.root)

    def test_external_absolute_fixture_is_accepted(self):
        doc = self.document()
        doc["artifacts"][0]["path"] = str(self.root / "artifacts/fixture.bin")
        checker.validate(self.write(doc), self.root)

    def test_artifact_tampering_is_rejected(self):
        doc = self.document()
        doc["artifacts"][1]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "artifact hash"):
            checker.validate(self.write(doc), self.root)

    def test_old_format_is_rejected(self):
        doc = self.document()
        doc["proof_format_version"] = 1
        with self.assertRaisesRegex(ValueError, "proof format"):
            checker.validate(self.write(doc), self.root)

    def test_duplicate_json_keys_are_rejected(self):
        path = self.root / "provenance/pcre-rss-phase-evidence.json"
        path.write_text('{"proof_format_version":2,"proof_format_version":2}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: proof_format_version"):
            checker.validate(path, self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
