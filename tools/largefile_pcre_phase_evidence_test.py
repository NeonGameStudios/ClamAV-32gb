#!/usr/bin/env python3
"""Regression tests for the fail-closed PCRE phase evidence contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
import largefile_pcre_phase_evidence as checker


class PcrePhaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="clamav-pcre-phase-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        (self.root / "provenance").mkdir()
        (self.root / "artifacts").mkdir()
        for filename, content in {
            "source-manifest.txt": "source\n",
            "build-identity.txt": "build\n",
            "config.txt": "config\n",
        }.items():
            (self.root / "provenance" / filename).write_text(content, encoding="utf-8")
        for filename, content in {
            "fixture.bin": b"fixture\n",
            "rss.tsv": b"phase\trss_kb\ttree_rss_kb\n",
            "scan-report.jsonl": b"DETECTION_TERMINATED\n",
            "process.log": (
                b"largefile_pcre_phase: phase=before-pcre subject_bytes=34359738368 subject_released=0\n"
                b"largefile_pcre_phase: phase=pcre subject_bytes=34359738368 subject_released=0\n"
                b"largefile_pcre_phase: phase=post-pcre-before-deep-parse subject_bytes=34359738368 subject_released=1\n"
                b"largefile_pcre_phase: phase=deep-parse recursion_level=0 subject_released=1\n"
            ),
        }.items():
            (self.root / "artifacts" / filename).write_bytes(content)

    def document(self):
        identity = {}
        for field, filename in {
            "source_manifest": "source-manifest.txt",
            "build_identity": "build-identity.txt",
            "config": "config.txt",
        }.items():
            path = self.root / "provenance" / filename
            identity[field] = {
                "path": f"provenance/{filename}",
                "sha256": checker.digest(path),
            }
        artifacts = []
        for role, filename in {
            "fixture": "fixture.bin",
            "rss-samples": "rss.tsv",
            "scan-report": "scan-report.jsonl",
            "process-log": "process.log",
        }.items():
            path = self.root / "artifacts" / filename
            artifacts.append({
                "role": role,
                "path": f"artifacts/{filename}",
                "sha256": checker.digest(path),
            })
        source_hash = identity["source_manifest"]["sha256"]
        return {
            "proof_format_version": 1,
            "evidence_type": "pcre-rss-phases",
            "qualification_result": "pass",
            "capability_kind": "matcher",
            "capability_id": "pcre",
            "source_manifest_sha256": source_hash,
            "platform": "Linux-x86_64",
            "budgets": {
                "pcre_rss_budget_kb": checker.PCRE_RSS_BUDGET_KB,
                "post_pcre_rss_budget_kb": checker.POST_PCRE_RSS_BUDGET_KB,
            },
            "identity": identity,
            "subject": {
                "case_id": "matcher:pcre:full-subject-tail",
                "fixture_sha256": hashlib.sha256(b"fixture").hexdigest(),
                "expected_signature": "LargeFile.PCRE.Tail.UNOFFICIAL",
                "detected_signature": "LargeFile.PCRE.Tail.UNOFFICIAL",
                "expected_offset": 34359738304,
                "detected_offset": 34359738304,
                "completion": "DETECTION_TERMINATED",
                "exit_code": 1,
            },
            "process_tree": {
                "root_pid": 101,
                "sampled_pids": [101, 102],
                "sample_source": "procfs-tree",
                "sampler": "/usr/local/bin/clamav-phase-sampler",
            },
            "samples": [
                {"sequence": 1, "timestamp_ns": 100, "phase": "before-pcre", "rss_kb": 1024, "tree_rss_kb": 2048},
                {"sequence": 2, "timestamp_ns": 200, "phase": "pcre", "rss_kb": 30000000, "tree_rss_kb": 40000000},
                {"sequence": 3, "timestamp_ns": 300, "phase": "post-pcre-before-deep-parse", "rss_kb": 8000000, "tree_rss_kb": 12000000 - 1},
                {"sequence": 4, "timestamp_ns": 400, "phase": "deep-parse", "rss_kb": 7000000, "tree_rss_kb": 11000000},
            ],
            "transition": {
                "subject_released": True,
                "deep_parse_started_after_release": True,
                "phase_markers_are_runtime_events": True,
            },
            "artifacts": artifacts,
        }

    def write(self, document=None):
        path = self.root / "provenance/pcre-rss-phase-evidence.json"
        path.write_text(json.dumps(document or self.document()), encoding="utf-8")
        return path

    def test_valid_complete_contract(self):
        checker.validate(self.write(), self.root)

    def test_missing_phase_is_rejected(self):
        document = self.document()
        document["samples"].pop(2)
        with self.assertRaisesRegex(ValueError, "do not cover"):
            checker.validate(self.write(document), self.root)

    def test_pcre_ceiling_is_enforced(self):
        document = self.document()
        document["samples"][1]["tree_rss_kb"] = checker.PCRE_RSS_BUDGET_KB + 1
        with self.assertRaisesRegex(ValueError, "40 GiB budget"):
            checker.validate(self.write(document), self.root)

    def test_post_pcre_headroom_is_enforced(self):
        document = self.document()
        document["samples"][2]["tree_rss_kb"] = checker.POST_PCRE_RSS_BUDGET_KB
        with self.assertRaisesRegex(ValueError, "12 GiB budget"):
            checker.validate(self.write(document), self.root)

    def test_out_of_order_samples_are_rejected(self):
        document = self.document()
        document["samples"][1]["timestamp_ns"] = 99
        with self.assertRaisesRegex(ValueError, "timestamps"):
            checker.validate(self.write(document), self.root)

    def test_exact_tail_proof_is_required(self):
        document = self.document()
        document["subject"]["detected_offset"] += 1
        with self.assertRaisesRegex(ValueError, "exact expected offset"):
            checker.validate(self.write(document), self.root)

    def test_subject_release_transition_is_required(self):
        document = self.document()
        document["transition"]["subject_released"] = False
        with self.assertRaisesRegex(ValueError, "full-subject release"):
            checker.validate(self.write(document), self.root)

    def test_runtime_marker_is_required(self):
        document = self.document()
        process_log = self.root / "artifacts/process.log"
        process_log.write_text(
            "largefile_pcre_phase: phase=before-pcre subject_bytes=34359738368 subject_released=0\n",
            encoding="utf-8",
        )
        document["artifacts"][-1]["sha256"] = checker.digest(process_log)
        with self.assertRaisesRegex(ValueError, "runtime marker"):
            checker.validate(self.write(document), self.root)

    def test_runtime_marker_order_is_required(self):
        document = self.document()
        process_log = self.root / "artifacts/process.log"
        process_log.write_text(
            "largefile_pcre_phase: phase=deep-parse recursion_level=0 subject_released=1\n"
            "largefile_pcre_phase: phase=before-pcre subject_bytes=34359738368 subject_released=0\n"
            "largefile_pcre_phase: phase=pcre subject_bytes=34359738368 subject_released=0\n"
            "largefile_pcre_phase: phase=post-pcre-before-deep-parse subject_bytes=34359738368 subject_released=1\n",
            encoding="utf-8",
        )
        document["artifacts"][-1]["sha256"] = checker.digest(process_log)
        with self.assertRaisesRegex(ValueError, "out of order"):
            checker.validate(self.write(document), self.root)

    def test_artifact_tampering_is_rejected(self):
        document = self.document()
        document["artifacts"][1]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "artifact hash"):
            checker.validate(self.write(document), self.root)

    def test_duplicate_json_keys_are_rejected(self):
        path = self.root / "provenance/pcre-rss-phase-evidence.json"
        path.write_text('{"proof_format_version":1,"proof_format_version":1}',
                        encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: proof_format_version"):
            checker.validate(path, self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
