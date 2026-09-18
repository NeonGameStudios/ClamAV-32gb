#!/usr/bin/env python3
"""Regression tests for the real R13 fanotify artifact binder."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
import largefile_fanotify_case_binder as binder
import largefile_fanotify_evidence as evidence


class FanotifyCaseBinderTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="clamav-fanotify-binder-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.raw = self.root / "raw"
        self.bound = self.root / "bound"
        self.raw.mkdir()
        self.fixture_hash = hashlib.sha256(b"clean fixture").hexdigest()
        self._write_inputs()

    def _write_jsonl(self, path: Path, rows):
        path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )

    def _write_inputs(self):
        raw_metadata = struct.pack(
            "<IBBH Qii", 24, 3, 0, 24,
            evidence.FAN_OPEN_PERM_MASK, 10, 1000,
        ).hex()
        self._write_jsonl(self.raw / "observer.jsonl", [{
            "event_id": 7,
            "event_kind": "FAN_OPEN_PERM",
            "target": True,
            "fixture_sha256": self.fixture_hash,
            "path": "/var/tmp/clamav-private-mount/fixture",
            "timestamp_ns": 7,
            "collector_pid": 99,
            "event_fd": 10,
            "event_pid": 1000,
            "event_len": 24,
            "metadata_len": 24,
            "mask": evidence.FAN_OPEN_PERM_MASK,
            "mask_names": ["FAN_OPEN_PERM"],
            "metadata_version": 3,
            "raw_metadata_hex": raw_metadata,
            "observer_response": "FAN_ALLOW",
        }])
        self.permission = {
            "artifact_kind": "clamonacc-permission-decision",
            "clamonacc_event_id": 101,
            "event_kind": "FAN_OPEN_PERM",
            "path": "/var/tmp/clamav-private-mount/fixture",
            "event_fd": 12,
            "event_pid": 1000,
            "event_len": 24,
            "metadata_len": 24,
            "metadata_version": 3,
            "mask": evidence.FAN_OPEN_PERM_MASK,
            "permission_response": "FAN_ALLOW",
            "response_written": True,
            "scan_status": 0,
            "scan_infected": 0,
            "scan_errors": 0,
            "timestamp_ns": 8,
        }
        self._write_jsonl(self.raw / "permission.jsonl", [self.permission])
        self._write_jsonl(self.raw / "actor.jsonl", [{
            "case_name": "clean",
            "fixture": "/var/tmp/clamav-private-mount/fixture",
            "fixture_sha256": self.fixture_hash,
            "actor_uid": 1000,
            "actor_exit_code": 0,
            "stderr": "",
            "event_id": 7,
            "observed_action": "allow",
            "opened": True,
        }])
        report = {
            "version": 1,
            "status": 0,
            "status_name": "No virus found",
            "verdict": 0,
            "completion": "COMPLETE",
            "target": "/var/tmp/clamav-private-mount/fixture",
            "root_size": 4096,
            "logical_bytes": 4096,
            "matcher_bytes": 4096,
            "contiguous_bytes": 4096,
            "temporary_bytes": 0,
            "files_scanned": 1,
            "max_recursion_depth": 0,
            "elapsed_ms": 1,
            "parser_operations": 1,
            "detector_operations": 1,
            "skipped_operations": 0,
            "clamonacc_event_id": 101,
        }
        self._write_jsonl(self.raw / "report.jsonl", [report])

    def _bind(self):
        return binder.bind(
            "clean", self.fixture_hash,
            self.raw / "observer.jsonl", self.raw / "permission.jsonl",
            self.raw / "actor.jsonl", self.raw / "report.jsonl",
            self.bound / "kernel.jsonl", self.bound / "actor.jsonl",
            self.bound / "report.jsonl",
        )

    def test_binds_real_inputs_and_revalidates_outputs(self):
        result = self._bind()
        self.assertEqual(result["event_id"], 7)
        self.assertEqual(result["clamonacc_event_id"], 101)
        kernel = json.loads((self.bound / "kernel.jsonl").read_text())
        report = json.loads((self.bound / "report.jsonl").read_text())
        self.assertEqual(kernel["permission_response"], "FAN_ALLOW")
        self.assertEqual(kernel["clamonacc_event_id"], 101)
        self.assertEqual(report["case_name"], "clean")
        self.assertEqual(report["fixture_sha256"], self.fixture_hash)
        self.assertEqual(report["scan_exit_code"], 0)

    def test_ambiguous_permission_match_is_rejected(self):
        duplicate = dict(self.permission)
        duplicate["clamonacc_event_id"] = 102
        self._write_jsonl(self.raw / "permission.jsonl", [self.permission, duplicate])
        with self.assertRaisesRegex(ValueError, "unambiguous match"):
            self._bind()

    def test_report_must_bind_clamonacc_event_id(self):
        report = json.loads((self.raw / "report.jsonl").read_text())
        report["clamonacc_event_id"] = 999
        self._write_jsonl(self.raw / "report.jsonl", [report])
        with self.assertRaisesRegex(ValueError, "not bound to clamonacc event 101"):
            self._bind()

    def test_failed_permission_write_is_not_qualified(self):
        permission = dict(self.permission)
        permission["response_written"] = False
        self._write_jsonl(self.raw / "permission.jsonl", [permission])
        with self.assertRaisesRegex(ValueError, "completed response write"):
            self._bind()

    def test_case_bound_raw_report_identity_is_not_overwritten(self):
        report = json.loads((self.raw / "report.jsonl").read_text())
        report["case_name"] = "clean"
        self._write_jsonl(self.raw / "report.jsonl", [report])
        with self.assertRaisesRegex(ValueError, "already case-bound"):
            self._bind()


if __name__ == "__main__":
    unittest.main(verbosity=2)
