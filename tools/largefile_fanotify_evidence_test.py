#!/usr/bin/env python3
"""Regression tests for the fail-closed fanotify evidence contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
import largefile_fanotify_evidence as checker


class FanotifyEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="clamav-fanotify-evidence-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        (self.root / "provenance").mkdir()
        (self.root / "logs").mkdir()
        for name, content in {
            "source-manifest.txt": "source\n",
            "build-identity.txt": "build\n",
            "config.txt": "config\n",
        }.items():
            (self.root / "provenance" / name).write_text(content, encoding="utf-8")
        for name in ("prevention", "monitoring"):
            (self.root / "logs" / f"{name}.log").write_text(name + "\n", encoding="utf-8")
        (self.root / "logs" / "events.log").write_text("FAN_OPEN_PERM\n", encoding="utf-8")
        (self.root / "logs" / "monitoring-report.log").write_text("report\n", encoding="utf-8")

    def document(self):
        identity = {}
        for field, filename in {
            "source_manifest": "source-manifest.txt",
            "build_identity": "build-identity.txt",
            "config": "config.txt",
        }.items():
            path = self.root / "provenance" / filename
            identity[field] = {"path": f"provenance/{filename}", "sha256": checker.digest(path)}
        prevention = []
        for index, (name, (completion, exit_code, decision, response)) in enumerate(
                checker.CASE_CONTRACT.items(), start=1):
            prevention.append({
                "name": name,
                "case_id": f"on-access:permission:{name}-edge",
                "fixture_sha256": hashlib.sha256(name.encode()).hexdigest(),
                "kernel_event": "FAN_OPEN_PERM",
                "event_id": index,
                "scan_completion": completion,
                "scan_exit_code": exit_code,
                "permission_decision": decision,
                "kernel_response": response,
                "observed_action": decision,
                "health": "pass",
                "cleanup": "pass",
                "artifacts": [
                    {"role": "kernel-event", "path": "logs/events.log",
                     "sha256": checker.digest(self.root / "logs/events.log")},
                    {"role": "scan-report", "path": "logs/prevention.log",
                     "sha256": checker.digest(self.root / "logs/prevention.log")},
                ],
            })
        monitoring = []
        for name, (completion, exit_code, _, _) in checker.CASE_CONTRACT.items():
            monitoring.append({
                "name": name,
                "scan_completion": completion,
                "scan_exit_code": exit_code,
                "permission_decision": "not-applicable",
                "kernel_response": "FAN_NO_PERMISSION",
                "observed_action": "allow",
                "health": "pass",
                "cleanup": "pass",
                "artifacts": [
                    {"role": "process-log", "path": "logs/monitoring.log",
                     "sha256": checker.digest(self.root / "logs/monitoring.log")},
                    {"role": "scan-report", "path": "logs/monitoring-report.log",
                     "sha256": checker.digest(self.root / "logs/monitoring-report.log")},
                ],
            })
        source_hash = identity["source_manifest"]["sha256"]
        return {
            "proof_format_version": 1,
            "evidence_type": "fanotify",
            "qualification_result": "pass",
            "capability_kind": "on-access",
            "capability_id": "permission",
            "source_manifest_sha256": source_hash,
            "platform": "Linux-x86_64",
            "mount": {
                "path": "/var/tmp/clamav-private-mount",
                "filesystem": "ext4",
                "private": True,
                "mounted": True,
                "permission_events": True,
                "monitoring_only": False,
            },
            "identity": identity,
            "prevention_cases": prevention,
            "monitoring_only": {
                "verified": True,
                "permission_events": False,
                "cases": monitoring,
            },
            "recovery_cleanup": {
                "monitor_stopped": True,
                "fanotify_fd_closed": True,
                "mount_unmounted": True,
                "fixtures_removed": True,
                "temporary_paths_removed": True,
                "daemon_healthy": True,
            },
        }

    def write(self, document=None):
        path = self.root / "provenance/fanotify-permission-evidence.json"
        path.write_text(json.dumps(document or self.document()), encoding="utf-8")
        return path

    def test_valid_complete_contract(self):
        checker.validate(self.write(), self.root)

    def test_missing_failure_case_is_rejected(self):
        document = self.document()
        document["prevention_cases"].pop()
        with self.assertRaisesRegex(ValueError, "do not cover"):
            checker.validate(self.write(document), self.root)

    def test_clean_case_cannot_deny(self):
        document = self.document()
        document["prevention_cases"][0]["permission_decision"] = "deny"
        document["prevention_cases"][0]["kernel_response"] = "FAN_DENY"
        document["prevention_cases"][0]["observed_action"] = "deny"
        with self.assertRaisesRegex(ValueError, "decision is wrong"):
            checker.validate(self.write(document), self.root)

    def test_monitoring_only_cannot_claim_permission_response(self):
        document = self.document()
        document["monitoring_only"]["permission_events"] = True
        with self.assertRaisesRegex(ValueError, "claims permission events"):
            checker.validate(self.write(document), self.root)

    def test_cleanup_is_mandatory(self):
        document = self.document()
        document["recovery_cleanup"]["mount_unmounted"] = False
        with self.assertRaisesRegex(ValueError, "mount_unmounted"):
            checker.validate(self.write(document), self.root)

    def test_identity_tampering_is_rejected(self):
        document = self.document()
        document["identity"]["config"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "config hash does not verify"):
            checker.validate(self.write(document), self.root)

    def test_retained_event_artifact_tampering_is_rejected(self):
        document = self.document()
        document["prevention_cases"][0]["artifacts"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "artifact hash does not verify"):
            checker.validate(self.write(document), self.root)

    def test_non_linux_proof_is_rejected(self):
        document = self.document()
        document["platform"] = "Darwin-arm64"
        with self.assertRaisesRegex(ValueError, "platform is not Linux"):
            checker.validate(self.write(document), self.root)

    def test_unknown_case_is_rejected(self):
        document = self.document()
        document["prevention_cases"][0]["name"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "unknown name"):
            checker.validate(self.write(document), self.root)

    def test_duplicate_json_keys_are_rejected(self):
        path = self.root / "provenance/fanotify-permission-evidence.json"
        path.write_text('{"proof_format_version":1,"proof_format_version":1}',
                        encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: proof_format_version"):
            checker.validate(path, self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
