#!/usr/bin/env python3
"""Regression tests for the fail-closed fanotify evidence contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import struct
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
        for index, name in enumerate(checker.CASE_CONTRACT, start=1):
            fixture_hash = hashlib.sha256(name.encode()).hexdigest()
            (self.root / "logs" / f"events-{name}.jsonl").write_text(
                json.dumps({
                    "event_id": index,
                    "event_kind": "FAN_OPEN_PERM",
                    "target": True,
                    "fixture_sha256": fixture_hash,
                    "path": f"/var/tmp/clamav-private-mount/{name}",
                    "timestamp_ns": index,
                    "collector_pid": 100,
                    "event_fd": 10,
                    "event_pid": 1000,
                    "event_len": 24,
                    "metadata_len": 24,
                    "mask": checker.FAN_OPEN_PERM_MASK,
                    "mask_names": ["FAN_OPEN_PERM"],
                    "metadata_version": 3,
                    "raw_metadata_hex": struct.pack(
                        "<IBBH Qii", 24, 3, 0, 24,
                        checker.FAN_OPEN_PERM_MASK, 10, 1000,
                    ).hex(),
                    "observer_response": "FAN_ALLOW",
                    "permission_response": "FAN_ALLOW" if name == "clean" else "FAN_DENY",
                }, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            (self.root / "logs" / f"actor-{name}.json").write_text(
                json.dumps({
                    "case_name": name,
                    "fixture_sha256": fixture_hash,
                    "event_id": index,
                    "opened": name == "clean",
                    "observed_action": "allow" if name == "clean" else "deny",
                    "actor_uid": 1000,
                    "actor_exit_code": 0 if name == "clean" else 1,
                    "stderr": "",
                }, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            completion, exit_code, _, _ = checker.CASE_CONTRACT[name]
            report = {
                "version": 1,
                "evidence_type": "on-access-scan",
                "case_name": name,
                "fixture_sha256": fixture_hash,
                "clamonacc_event_id": index,
                "scan_exit_code": exit_code,
                "completion": completion,
                "status": 0 if name in {"clean", "detection"} else 1,
                "verdict": 0 if name != "detection" else 2,
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
                "last_alert": "R13.Test.Detection" if name == "detection" else None,
                "last_alert_offset": 32 if name == "detection" else None,
                "reason": None if name in {"clean", "detection"} else f"{name} test failure",
            }
            (self.root / "logs" / f"scan-{name}.jsonl").write_text(
                json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
            )
        (self.root / "logs" / "monitoring.log").write_text("monitoring\n", encoding="utf-8")
        for name in checker.CASE_CONTRACT:
            fixture_hash = hashlib.sha256(name.encode()).hexdigest()
            completion, exit_code, _, _ = checker.CASE_CONTRACT[name]
            report = {
                "version": 1,
                "evidence_type": "on-access-scan",
                "case_name": name,
                "fixture_sha256": fixture_hash,
                "clamonacc_event_id": 0,
                "scan_exit_code": exit_code,
                "completion": completion,
                "status": 0 if name in {"clean", "detection"} else 1,
                "verdict": 0 if name != "detection" else 2,
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
                "last_alert": "R13.Test.Detection" if name == "detection" else None,
                "last_alert_offset": 32 if name == "detection" else None,
                "reason": None if name in {"clean", "detection"} else f"{name} test failure",
            }
            (self.root / "logs" / f"monitor-scan-{name}.jsonl").write_text(
                json.dumps(report, sort_keys=True) + "\n", encoding="utf-8"
            )

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
                    {"role": "kernel-event", "path": f"logs/events-{name}.jsonl",
                     "sha256": checker.digest(self.root / f"logs/events-{name}.jsonl")},
                    {"role": "actor-result", "path": f"logs/actor-{name}.json",
                     "sha256": checker.digest(self.root / f"logs/actor-{name}.json")},
                    {"role": "scan-report", "path": f"logs/scan-{name}.jsonl",
                     "sha256": checker.digest(self.root / f"logs/scan-{name}.jsonl")},
                ],
            })
        monitoring = []
        for name, (completion, exit_code, _, _) in checker.CASE_CONTRACT.items():
            monitoring.append({
                "name": name,
                "fixture_sha256": hashlib.sha256(name.encode()).hexdigest(),
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
                    {"role": "scan-report", "path": f"logs/monitor-scan-{name}.jsonl",
                     "sha256": checker.digest(self.root / f"logs/monitor-scan-{name}.jsonl")},
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

    def test_plain_event_text_is_not_kernel_event_evidence(self):
        document = self.document()
        path = self.root / "logs/events-clean.jsonl"
        path.write_text("FAN_OPEN_PERM\n", encoding="utf-8")
        document["prevention_cases"][0]["artifacts"][0]["sha256"] = checker.digest(path)
        with self.assertRaisesRegex(ValueError, "invalid JSON"):
            checker.validate(self.write(document), self.root)

    def test_actor_result_must_bind_observed_action(self):
        document = self.document()
        path = self.root / "logs/actor-clean.json"
        actor = json.loads(path.read_text(encoding="utf-8"))
        actor["observed_action"] = "deny"
        path.write_text(json.dumps(actor) + "\n", encoding="utf-8")
        document["prevention_cases"][0]["artifacts"][1]["sha256"] = checker.digest(path)
        with self.assertRaisesRegex(ValueError, "contradicts"):
            checker.validate(self.write(document), self.root)

    def test_actor_exit_must_bind_open_observation(self):
        document = self.document()
        path = self.root / "logs/actor-clean.json"
        actor = json.loads(path.read_text(encoding="utf-8"))
        actor["actor_exit_code"] = 1
        path.write_text(json.dumps(actor) + "\n", encoding="utf-8")
        document["prevention_cases"][0]["artifacts"][1]["sha256"] = checker.digest(path)
        with self.assertRaisesRegex(ValueError, "exit code contradicts"):
            checker.validate(self.write(document), self.root)

    def test_kernel_event_requires_one_target_event(self):
        document = self.document()
        path = self.root / "logs/events-clean.jsonl"
        original = path.read_text(encoding="utf-8")
        event = json.loads(original)
        event["event_id"] = 99
        event["path"] = "/var/tmp/clamav-private-mount/extra"
        path.write_text(original + json.dumps(event) + "\n", encoding="utf-8")
        document["prevention_cases"][0]["artifacts"][0]["sha256"] = checker.digest(path)
        with self.assertRaisesRegex(ValueError, "exactly one target-bound event"):
            checker.validate(self.write(document), self.root)

    def test_kernel_event_must_bind_clamav_permission_response(self):
        document = self.document()
        path = self.root / "logs/events-clean.jsonl"
        event = json.loads(path.read_text(encoding="utf-8"))
        del event["permission_response"]
        path.write_text(json.dumps(event) + "\n", encoding="utf-8")
        document["prevention_cases"][0]["artifacts"][0]["sha256"] = checker.digest(path)
        with self.assertRaisesRegex(ValueError, "ClamAV's explicit permission response"):
            checker.validate(self.write(document), self.root)

    def test_monitoring_scan_report_must_be_structured_and_case_bound(self):
        document = self.document()
        path = self.root / "logs/monitor-scan-clean.jsonl"
        report = json.loads(path.read_text(encoding="utf-8"))
        report["case_name"] = "detection"
        path.write_text(json.dumps(report) + "\n", encoding="utf-8")
        for case in document["monitoring_only"]["cases"]:
            if case["name"] == "clean":
                for artifact in case["artifacts"]:
                    if artifact["role"] == "scan-report":
                        artifact["sha256"] = checker.digest(path)
        with self.assertRaisesRegex(ValueError, "monitoring-only case clean scan report.*not bound to case clean"):
            checker.validate(self.write(document), self.root)

    def test_scan_report_must_bind_case_and_outcome(self):
        document = self.document()
        path = self.root / "logs/scan-clean.jsonl"
        report = json.loads(path.read_text(encoding="utf-8"))
        report["case_name"] = "detection"
        path.write_text(json.dumps(report) + "\n", encoding="utf-8")
        document["prevention_cases"][0]["artifacts"][2]["sha256"] = checker.digest(path)
        with self.assertRaisesRegex(ValueError, "not bound to case clean"):
            checker.validate(self.write(document), self.root)

    def test_scan_report_must_bind_permission_event_id(self):
        document = self.document()
        path = self.root / "logs/scan-clean.jsonl"
        report = json.loads(path.read_text(encoding="utf-8"))
        report["clamonacc_event_id"] = 99
        path.write_text(json.dumps(report) + "\n", encoding="utf-8")
        document["prevention_cases"][0]["artifacts"][2]["sha256"] = checker.digest(path)
        with self.assertRaisesRegex(ValueError, "not bound to clamonacc event 1"):
            checker.validate(self.write(document), self.root)

    def test_scan_report_must_be_structured(self):
        document = self.document()
        path = self.root / "logs/scan-clean.jsonl"
        path.write_text("report\\n", encoding="utf-8")
        document["prevention_cases"][0]["artifacts"][2]["sha256"] = checker.digest(path)
        with self.assertRaisesRegex(ValueError, "invalid JSON"):
            checker.validate(self.write(document), self.root)

    def test_raw_event_header_must_match_structured_fields(self):
        document = self.document()
        path = self.root / "logs/events-clean.jsonl"
        event = json.loads(path.read_text(encoding="utf-8"))
        event["event_pid"] = 1001
        path.write_text(json.dumps(event) + "\n", encoding="utf-8")
        document["prevention_cases"][0]["artifacts"][0]["sha256"] = checker.digest(path)
        with self.assertRaisesRegex(ValueError, "raw metadata does not match"):
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
