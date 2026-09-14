#!/usr/bin/env python3
"""Bounded input-policy controls; synthetic metadata is never release evidence.

Run with Python's standard library only. The exact-edge positive control mocks
filesystem metadata in this test process; no 32-GiB file or scan is performed.
Production entry points retain their unconditional qualification requirements.
"""

from __future__ import annotations

import copy
import csv
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
import largefile_service_workload_check as checker


class InputPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="clamav-input-policy-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.data = b"written materialized fixture\n" * 256
        self.input = self.root / "input.bin"
        self.input.write_bytes(self.data)
        self.digest = hashlib.sha256(self.data).hexdigest()

    def oracle(self, edge_size=checker.EXACT_EDGE_BYTES, materialized_size=None):
        sizes = {role: len(self.data) for role in checker.INPUT_ROLES}
        sizes["edge"] = edge_size
        if materialized_size is not None:
            sizes["materialized"] = materialized_size
        return {
            role: (sizes[role], self.digest, 0, "COMPLETE", "-", "-", "CL_TYPE_DATA")
            for role in checker.INPUT_ROLES
        }

    def write_oracle(self, path=None, **kwargs):
        path = path or self.root / "oracle.tsv"
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream, delimiter="\t")
            writer.writerow(checker.ORACLE_HEADER)
            for role, row in self.oracle(**kwargs).items():
                writer.writerow((role, *row))
        return path

    def metadata(self, **changes):
        actual = self.input.stat()
        values = {name: getattr(actual, name) for name in (
            "st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"
        )}
        values["st_blocks"] = getattr(actual, "st_blocks", 16)
        values.update(changes)
        return SimpleNamespace(**values)

    def test_oracle_requires_exact_edge(self):
        for size in (0, 1, checker.EXACT_EDGE_BYTES - 1, checker.EXACT_EDGE_BYTES + 1):
            with self.subTest(size=size):
                with self.assertRaisesRegex(RuntimeError, "edge input must be exactly"):
                    checker.load_oracle(self.write_oracle(edge_size=size))
        oracle = checker.load_oracle(self.write_oracle())
        self.assertEqual(oracle["edge"][0], 34359738368)

    def test_materialized_must_be_nonempty(self):
        with self.assertRaisesRegex(RuntimeError, "materialized input must be nonempty"):
            checker.load_oracle(self.write_oracle(materialized_size=0))
        self.assertEqual(checker.load_oracle(self.write_oracle(materialized_size=1))["materialized"][0], 1)

    def test_malformed_tsv_quoting_is_rejected(self):
        malformed = self.root / "malformed.tsv"
        malformed.write_text(
            "\t".join(checker.ORACLE_HEADER) + "\n\"unterminated\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "qualification oracle has malformed TSV"):
            checker.read_tsv(malformed, checker.ORACLE_HEADER, "qualification oracle")

    def test_tsv_row_width_is_rejected_at_ingress(self):
        malformed = self.root / "short.tsv"
        malformed.write_text(
            "\t".join(checker.ORACLE_HEADER) + "\nrole\t1\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "qualification oracle has 2 columns at line 2"):
            checker.read_tsv(malformed, checker.ORACLE_HEADER, "qualification oracle")

    def test_tsv_empty_field_is_rejected_at_ingress(self):
        malformed = self.root / "empty.tsv"
        malformed.write_text(
            "\t".join(checker.ORACLE_HEADER) + "\n"
            + "\t".join(("production", "1", "0" * 64, "0", "COMPLETE", "-", "-", ""))
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(RuntimeError, "qualification oracle has an empty field at line 2"):
            checker.read_tsv(malformed, checker.ORACLE_HEADER, "qualification oracle")

    def test_symlinked_service_evidence_path_is_rejected(self):
        logs = self.root / "logs"
        logs.mkdir()
        target = logs / "target.log"
        target.write_text("target\n", encoding="utf-8")
        (logs / "link.log").symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "is symlinked"):
            checker.evidence_path(self.root, "logs/link.log", "service log")

    def test_legacy_edge_workloads_are_not_report_bindings(self):
        expected = checker.expected_workloads()
        for label in ("edge_contscan", "edge_multiscan", "edge_allmatch",
                      "edge_fildes", "edge_instream"):
            with self.subTest(label=label):
                self.assertEqual(expected[label], ("legacy", "edge", False))
        log = self.root / "legacy.log"
        log.write_text("protocol_mode=CONTSCAN\nfixture: OK\n", encoding="utf-8")
        edge_oracle = (
            checker.EXACT_EDGE_BYTES, self.digest, 0, "COMPLETE", "-", "-", "CL_TYPE_DATA"
        )
        checker.validate_legacy_log(log, "edge_contscan", edge_oracle, "CONTSCAN")

    def test_clamdscan_mode_combinations_are_report_bindings(self):
        expected = checker.expected_workloads()
        for label in (
            "edge-clamdscan-multiscan",
            "edge-clamdscan-stream-multiscan",
            "edge-clamdscan-fdpass-multiscan",
        ):
            with self.subTest(label=label):
                self.assertEqual(expected[label], ("service", "edge", False))

    def test_legacy_verifier_rejects_status_that_disagrees_with_oracle(self):
        expected = checker.expected_workloads()
        self.assertEqual(expected["edge_contscan"], ("legacy", "edge", False))
        edge_oracle = (
            checker.EXACT_EDGE_BYTES, self.digest, 1, "DETECTION_TERMINATED",
            "Legacy.Detection", "7", "CL_TYPE_DATA"
        )
        log = self.root / "legacy-detection.log"
        log.write_text(
            "protocol_mode=CONTSCAN\nfixture: Legacy.Detection.UNOFFICIAL FOUND\n",
            encoding="utf-8",
        )
        checker.validate_legacy_log(log, "edge_contscan", edge_oracle, "CONTSCAN")
        with self.assertRaisesRegex(RuntimeError, "does not match oracle"):
            checker.validate_process_status("edge_contscan", 0, edge_oracle)

    def test_valid_exact_edge_with_test_local_filesystem_metadata(self):
        """Exercise real binding/hash logic while mocking only giant-file metadata."""
        info = self.metadata(st_size=checker.EXACT_EDGE_BYTES,
                             st_blocks=checker.EXACT_EDGE_BYTES // 512)
        with mock.patch.object(checker.os, "fstat", return_value=info), \
                mock.patch.object(Path, "stat", return_value=info), \
                mock.patch.object(checker.os, "SEEK_HOLE", 4, create=True), \
                mock.patch.object(checker.os, "lseek", return_value=checker.EXACT_EDGE_BYTES):
            record = checker.input_binding(str(self.input), "edge", self.oracle())
        self.assertEqual(record["size"], checker.EXACT_EDGE_BYTES)
        self.assertEqual(record["allocated_bytes"], checker.EXACT_EDGE_BYTES)
        self.assertEqual(record["first_hole"], checker.EXACT_EDGE_BYTES)
        self.assertEqual(record["sha256"], self.digest)

    def test_allocation_missing_invalid_or_short_fails_before_hole_query(self):
        for blocks in (None, -1, True, 1.5, 0):
            with self.subTest(blocks=blocks):
                info = self.metadata(st_blocks=blocks)
                if blocks is None:
                    del info.st_blocks
                with self.input.open("rb") as stream, \
                        mock.patch.object(checker.os, "lseek") as seek:
                    with self.assertRaisesRegex(RuntimeError, "not fully allocated"):
                        checker.input_layout(stream, "materialized", info)
                    seek.assert_not_called()

    def test_interior_hole_rejected_even_with_sufficient_blocks(self):
        info = self.metadata(st_blocks=1024)
        with self.input.open("rb") as stream, \
                mock.patch.object(checker.os, "SEEK_HOLE", 4, create=True), \
                mock.patch.object(checker.os, "lseek", return_value=4096):
            with self.assertRaisesRegex(RuntimeError, "contains a reported hole"):
                checker.input_layout(stream, "materialized", info)

    def test_unsupported_hole_query_fails_closed(self):
        info = self.metadata(st_blocks=1024)
        with self.input.open("rb") as stream, \
                mock.patch.object(checker.os, "SEEK_HOLE", 4, create=True), \
                mock.patch.object(checker.os, "lseek", side_effect=OSError(errno.EINVAL, "unsupported")):
            with self.assertRaisesRegex(RuntimeError, "filesystem hole query failed"):
                checker.input_layout(stream, "edge", info)

    def test_missing_hole_api_fails_closed(self):
        info = self.metadata(st_blocks=1024)
        # Replace the module reference, not the real process-wide os module.
        with self.input.open("rb") as stream, mock.patch.object(checker, "os", SimpleNamespace()):
            with self.assertRaisesRegex(RuntimeError, "hole queries are unavailable"):
                checker.input_layout(stream, "materialized", info)

    @unittest.skipUnless(sys.platform.startswith("linux"), "qualification filesystem control requires Linux")
    def test_real_written_materialized_file(self):
        with self.input.open("rb") as stream:
            os.fsync(stream.fileno())
        record = checker.input_binding(str(self.input), "materialized", self.oracle())
        self.assertGreaterEqual(record["allocated_bytes"], len(self.data))
        self.assertEqual(record["first_hole"], len(self.data))

    @unittest.skipUnless(sys.platform.startswith("linux"), "qualification filesystem control requires Linux")
    def test_real_sparse_materialized_file_rejected_before_hashing(self):
        sparse = self.root / "sparse.bin"
        size = 1024 * 1024
        with sparse.open("wb") as stream:
            stream.truncate(size)
        oracle = self.oracle(materialized_size=size)
        with mock.patch.object(checker.hashlib, "sha256") as digest:
            with self.assertRaisesRegex(RuntimeError, "not fully allocated"):
                checker.input_binding(str(sparse), "materialized", oracle)
            digest.assert_not_called()

    def test_hash_mismatch(self):
        oracle = self.oracle()
        oracle["production"] = (len(self.data), "0" * 64, *oracle["production"][2:])
        with self.assertRaisesRegex(RuntimeError, "SHA-256 changed"):
            checker.input_binding(str(self.input), "production", oracle)

    def test_same_descriptor_mutation_rejected(self):
        before = self.metadata()
        after = self.metadata(st_mtime_ns=before.st_mtime_ns + 1)
        with mock.patch.object(checker.os, "fstat", side_effect=[before, after]) as fstat:
            with self.assertRaisesRegex(RuntimeError, "changed while binding"):
                checker.input_binding(str(self.input), "production", self.oracle())
        self.assertEqual(fstat.call_args_list[0].args, fstat.call_args_list[1].args)

    def test_path_replaced_after_open_rejected(self):
        info = self.metadata()
        replaced = self.metadata(st_ino=info.st_ino + 1)
        with mock.patch.object(checker.os, "fstat", return_value=info), \
                mock.patch.object(Path, "stat", return_value=replaced):
            with self.assertRaisesRegex(RuntimeError, "changed while binding"):
                checker.input_binding(str(self.input), "production", self.oracle())

    def test_nonregular_descriptor_rejected_before_hashing(self):
        info = self.metadata(st_mode=stat.S_IFIFO | 0o600)
        with mock.patch.object(checker.os, "fstat", return_value=info), \
                mock.patch.object(checker.hashlib, "sha256") as digest:
            with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                checker.input_binding(str(self.input), "production", self.oracle())
            digest.assert_not_called()

    def test_actual_size_must_match_oracle(self):
        oracle = self.oracle()
        oracle["production"] = (len(self.data) + 1, *oracle["production"][1:])
        with self.assertRaisesRegex(RuntimeError, "input size changed"):
            checker.input_binding(str(self.input), "production", oracle)

    def test_invalid_role_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "invalid oracle role"):
            checker.input_binding(str(self.input), "unknown", self.oracle())

    def write_evidence(self):
        provenance = self.root / "provenance"
        provenance.mkdir(exist_ok=True)
        record = checker.input_binding(str(self.input), "production", self.oracle())
        inputs = {role: dict(record) for role in checker.INPUT_ROLES}
        evidence = {"version": 1, "inputs": inputs}
        for phase in ("before", "after"):
            (provenance / f"service-inputs-{phase}.json").write_text(json.dumps(evidence))
        return evidence

    def test_matching_provenance_and_missing_phases(self):
        evidence = self.write_evidence()
        self.assertEqual(checker.input_evidence(self.root), evidence["inputs"])
        for phase in ("before", "after"):
            with self.subTest(phase=phase):
                self.write_evidence()
                (self.root / f"provenance/service-inputs-{phase}.json").unlink()
                with self.assertRaises(FileNotFoundError):
                    checker.input_evidence(self.root)

    def test_before_after_provenance_tampering(self):
        for phase in ("before", "after"):
            with self.subTest(phase=phase):
                evidence = self.write_evidence()
                evidence["inputs"]["edge"]["allocated_bytes"] = 0
                (self.root / f"provenance/service-inputs-{phase}.json").write_text(json.dumps(evidence))
                with self.assertRaisesRegex(RuntimeError, "changed during qualification"):
                    checker.input_evidence(self.root)

    def test_provenance_schema(self):
        valid = self.write_evidence()
        missing_role = copy.deepcopy(valid)
        del missing_role["inputs"]["edge"]
        for evidence in ({}, [], {"version": 2, "inputs": valid["inputs"]}, missing_role):
            with self.subTest(evidence=evidence):
                self.write_evidence()
                (self.root / "provenance/service-inputs-before.json").write_text(json.dumps(evidence))
                with self.assertRaisesRegex(RuntimeError, "invalid schema"):
                    checker.input_evidence(self.root)

    def test_provenance_duplicate_json_keys_are_rejected(self):
        self.write_evidence()
        path = self.root / "provenance/service-inputs-before.json"
        path.write_text(
            '{"version":1,"version":1,"inputs":{}}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: version"):
            checker.input_evidence(self.root)

    def test_matching_but_forged_provenance_rechecked_against_input(self):
        evidence = self.write_evidence()
        for phase in ("before", "after"):
            evidence["inputs"]["production"]["sha256"] = "0" * 64
            (self.root / f"provenance/service-inputs-{phase}.json").write_text(json.dumps(evidence))
        oracle_path = self.write_oracle(self.root / "provenance/qualification-oracle.tsv")
        workloads = self.root / "provenance/service-workload-results.tsv"
        with workloads.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream, delimiter="\t")
            writer.writerow(checker.WORKLOAD_HEADER)
            writer.writerow(("production-clamscan", "cli", "production", str(self.input),
                             "logs/production.log", "reports/production.jsonl", "0", "yes"))
        (self.root / "logs").mkdir()
        (self.root / "reports").mkdir()
        (self.root / "logs/production.log").write_text("placeholder\n", encoding="utf-8")
        (self.root / "reports/production.jsonl").write_text("{}\n", encoding="utf-8")
        (self.root / "oracle-binding.txt").write_text(
            "qualification_oracle=provenance/qualification-oracle.tsv\n"
            f"qualification_oracle_sha256={checker.sha256(oracle_path)}\n"
            "workload_results=provenance/service-workload-results.tsv\n"
            f"workload_results_sha256={checker.sha256(workloads)}\n"
        )
        with self.assertRaisesRegex(RuntimeError, "recorded allocation/content evidence"):
            checker.main([str(self.root)])

    def test_unmodified_cli_rejects_tiny_edge_before_scanning(self):
        oracle = self.write_oracle(edge_size=len(self.data))
        command = [sys.executable, "-B", str(Path(checker.__file__).resolve()),
                   "--check-inputs", str(oracle), *([str(self.input)] * 4)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("edge input must be exactly 34359738368", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_unmodified_evidence_cli_rejects_tiny_edge(self):
        (self.root / "provenance").mkdir()
        self.write_oracle(self.root / "provenance/qualification-oracle.tsv", edge_size=1)
        (self.root / "provenance/service-workload-results.tsv").write_text("\t".join(checker.WORKLOAD_HEADER) + "\n")
        result = subprocess.run([sys.executable, "-B", str(Path(checker.__file__).resolve()), str(self.root)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("edge input must be exactly 34359738368", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
