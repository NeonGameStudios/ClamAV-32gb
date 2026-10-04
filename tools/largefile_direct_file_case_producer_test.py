"""Synthetic controls for the R04 direct-file producer; not qualification."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import largefile_direct_input_capture as capture
import largefile_direct_file_case_producer as producer
import largefile_acceptance_resources as resources


REPO = Path(__file__).resolve().parent.parent


class DirectFileProducerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "evidence"
        provenance = self.root / "provenance"
        provenance.mkdir(parents=True)
        (self.root / "tmp").mkdir()
        self.fixture = Path(self.temp.name).resolve() / "external.bin"
        self.fixture.write_bytes(b"independent direct fixture\n")
        self.identity = capture.input_identity(self.fixture)
        self.case_id = "clamscan:file:clean-edge"
        wrapper = REPO / "tools/largefile_acceptance_resource_capture.py"
        wrapper_hash = hashlib.sha256(wrapper.read_bytes()).hexdigest()
        for name, value in (
            ("source-content.sha256", f"{wrapper_hash}  tools/largefile_acceptance_resource_capture.py\n".encode()),
            ("CMakeCache.txt", b"CMake cache\n"),
            ("database.ndb", b"Test.Direct:0:*:414243\n"),
        ):
            (provenance / name).write_bytes(value)
        shutil.copyfile(Path(sys.executable).resolve(), provenance / "clamscan")
        hashes = {
            name: hashlib.sha256((provenance / name).read_bytes()).hexdigest()
            for name in ("source-content.sha256", "clamscan", "CMakeCache.txt", "database.ndb")
        }
        oracle = {
            "version": 1, "case_id": self.case_id, "fixture_role": "direct-raw",
            "input": str(self.fixture), "size": self.identity["size"],
            "sha256": self.identity["sha256"], "completion": "COMPLETE",
            "exit_code": 0, "alert_signature": "-", "alert_offset": None,
            "alert_offset_scope": "none",
            "reason": "complete",
            "source_manifest_sha256": hashes["source-content.sha256"],
            "build_identity_sha256": hashes["clamscan"],
            "config_sha256": hashes["CMakeCache.txt"],
            "database_sha256": hashes["database.ndb"],
        }
        self.oracle_path = provenance / "direct-oracle.json"
        self.oracle_path.write_text(json.dumps(oracle) + "\n", encoding="utf-8")
        input_record = {"version": 1, "inputs": {"direct-raw": self.identity}}
        capture.exclusive_json(provenance / "direct-inputs-before.json", input_record)
        capture.exclusive_json(provenance / "direct-inputs-after.json", input_record)
        command = [
            sys.executable, "-B",
            str(wrapper),
            str(self.root), "--kind", "clamscan", "--id", "file",
            "--case-id", self.case_id,
            "--source-manifest", "provenance/source-content.sha256",
            "--build-identity", "provenance/clamscan",
            "--config", "provenance/CMakeCache.txt",
            "--temporary-root", "tmp",
            "--process-log", "provenance/scan.log",
            "--sample-log", "provenance/samples.tsv", "--",
            str(Path(sys.executable).resolve()),
            f"--database={provenance / 'database.ndb'}",
            f"--report-json={self.root / 'scan-report.jsonl'}",
            f"--tempdir={self.root / 'tmp'}",
            "--max-filesize=32G", "--max-scansize=64G",
            "--max-temporary-size=64G", "--max-contiguous-size=32G",
            "--log-hash", "--debug", "--no-summary",
            "--alert-exceeds-max=yes", str(self.fixture),
        ]
        self.command_path = provenance / "direct-command-result.json"
        self.command_path.write_text(json.dumps({
            "version": 1, "command": command, "exit_code": 0,
            "input_stable": True,
            "oracle_sha256": hashlib.sha256(self.oracle_path.read_bytes()).hexdigest(),
        }) + "\n", encoding="utf-8")
        report = {
            "version": 1, "target": str(self.fixture),
            "root_size": self.identity["size"], "status": 0, "verdict": 0,
            "completion": "COMPLETE", "logical_bytes": self.identity["size"],
            "matcher_bytes": self.identity["size"], "contiguous_bytes": 0,
            "temporary_bytes": 0, "files_scanned": 1,
            "max_recursion_depth": 0, "elapsed_ms": 1,
            "parser_operations": 1, "detector_operations": 1,
            "skipped_operations": 0,
        }
        (self.root / "scan-report.jsonl").write_text(json.dumps(report) + "\n", encoding="utf-8")
        (provenance / "scan.log").write_text(
            f"{self.fixture} FileHash: {self.identity['sha256']} (sha2-256)\n"
            f"{self.fixture}: OK\n", encoding="utf-8",
        )
        (provenance / "samples.tsv").write_text("synthetic sample control\n", encoding="utf-8")
        row = {field: "0" for field in resources.RESOURCE_HEADER}
        row.update({
            "kind": "clamscan", "id": "file", "case_id": self.case_id,
            "source_manifest_sha256": hashes["source-content.sha256"],
            "build_identity_sha256": hashes["clamscan"],
            "config_sha256": hashes["CMakeCache.txt"],
            "platform": "Linux-x86_64", "sample_source": "procfs-process-tree",
            "sample_count": "1", "rss_peak_kb": "1000", "pss_peak_kb": "500",
            "vas_peak_kb": "2000", "oom_cgroup_count": "1",
            "oom_cgroup_digest": "a" * 64,
            "pcre_rss_peak_kb": "-", "post_pcre_rss_peak_kb": "-",
        })
        with (provenance / "acceptance-case-resources.tsv").open(
            "w", newline="", encoding="utf-8"
        ) as stream:
            writer = csv.DictWriter(stream, fieldnames=resources.RESOURCE_HEADER,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerow(row)

    def produce(self) -> Path:
        with mock.patch.object(producer.os, "uname", return_value=SimpleNamespace(
            sysname="Linux", machine="x86_64"
        )):
            return producer.produce(
                self.root, REPO / "docs/largefile-capabilities.tsv",
                REPO / "docs/largefile-capability-case-map.tsv", "development",
            )

    def limit_edge_command(self) -> dict:
        result = json.loads(self.command_path.read_text(encoding="utf-8"))
        command = result["command"]
        command[command.index("--case-id") + 1] = "clamscan:file:limit-edge"
        command.remove("--max-contiguous-size=32G")
        command[command.index("--alert-exceeds-max=yes")] = "--alert-exceeds-max=no"
        return result

    def validate_limit_edge_command(self, result: dict) -> int:
        return producer.validate_command(
            self.root, result, self.identity,
            hashlib.sha256(self.oracle_path.read_bytes()).hexdigest(),
            "clamscan:file:limit-edge",
            hashlib.sha256((self.root / "provenance/clamscan").read_bytes()).hexdigest(),
        )

    def test_development_control_binds_external_input_and_resources(self) -> None:
        records = self.produce()
        self.assertEqual(len(records.read_text().splitlines()), 2)
        self.assertEqual(self.fixture.read_bytes(), b"independent direct fixture\n")

    def test_changed_oracle_rejected_before_record(self) -> None:
        oracle = json.loads(self.oracle_path.read_text())
        oracle["database_sha256"] = "0" * 64
        self.oracle_path.write_text(json.dumps(oracle), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not bind|oracle evidence"):
            self.produce()
        self.assertFalse((self.root / "provenance/acceptance-cases.tsv").exists())

    def test_unbound_command_input_rejected_before_record(self) -> None:
        result = json.loads(self.command_path.read_text())
        result["command"][-1] = "/tmp/not-the-scanned-input"
        self.command_path.write_text(json.dumps(result), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "bound scanner on the bound input"):
            self.produce()
        self.assertFalse((self.root / "provenance/acceptance-cases.tsv").exists())

    def test_duplicate_limit_override_rejected(self) -> None:
        result = json.loads(self.command_path.read_text())
        result["command"].insert(-1, "--max-filesize=1G")
        self.command_path.write_text(json.dumps(result), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "one bound --max-filesize"):
            self.produce()
        self.assertFalse((self.root / "provenance/acceptance-cases.tsv").exists())

    def test_limit_edge_requires_alerting_disabled(self) -> None:
        result = self.limit_edge_command()
        self.assertEqual(self.validate_limit_edge_command(result), 0)

        result["command"][result["command"].index("--alert-exceeds-max=no")] = \
            "--alert-exceeds-max=yes"
        with self.assertRaisesRegex(ValueError, "alert-exceeds-max=no"):
            self.validate_limit_edge_command(result)

    def test_unbound_resource_wrapper_rejected(self) -> None:
        manifest = self.root / "provenance/source-content.sha256"
        manifest.write_text("0" * 64 + "  tools/largefile_acceptance_resource_capture.py\n")
        oracle = json.loads(self.oracle_path.read_text())
        oracle["source_manifest_sha256"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
        self.oracle_path.write_text(json.dumps(oracle), encoding="utf-8")
        command = json.loads(self.command_path.read_text())
        command["oracle_sha256"] = hashlib.sha256(self.oracle_path.read_bytes()).hexdigest()
        self.command_path.write_text(json.dumps(command), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "wrapper is not bound"):
            self.produce()
        self.assertFalse((self.root / "provenance/acceptance-cases.tsv").exists())

    def test_release_label_rejects_small_fixture(self) -> None:
        with mock.patch.object(producer.os, "uname", return_value=SimpleNamespace(
            sysname="Linux", machine="x86_64"
        )):
            with self.assertRaisesRegex(ValueError, "lacks the exact edge size"):
                producer.produce(
                    self.root, REPO / "docs/largefile-capabilities.tsv",
                    REPO / "docs/largefile-capability-case-map.tsv", "release",
                )


if __name__ == "__main__":
    unittest.main()
