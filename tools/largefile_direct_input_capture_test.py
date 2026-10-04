"""Focused copy-free direct-input capture controls."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
import hashlib

import largefile_direct_input_capture as capture


class DirectInputCaptureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "case"
        self.root.mkdir()
        self.input = Path(self.temp.name) / "input.bin"
        self.input.write_bytes(b"known input\n")

    def sidecars(self) -> tuple[bytes, bytes]:
        provenance = self.root / "provenance"
        return ((provenance / "direct-inputs-before.json").read_bytes(),
                (provenance / "direct-inputs-after.json").read_bytes())

    def independent_oracle(self) -> dict:
        provenance = self.root / "provenance"
        provenance.mkdir()
        hashes = {}
        for name in ("source-content.sha256", "clamscan", "CMakeCache.txt", "database.ndb"):
            data = (name + "\n").encode()
            (provenance / name).write_bytes(data)
            hashes[name] = hashlib.sha256(data).hexdigest()
        identity = capture.input_identity(self.input)
        return {
            "version": 1, "fixture_role": "edge", "input": str(self.input),
            "size": identity["size"], "sha256": identity["sha256"],
            "case_id": "clamscan:file:clean-edge", "completion": "COMPLETE",
            "exit_code": 0, "alert_signature": "-", "alert_offset": None,
            "alert_offset_scope": "none",
            "reason": "complete",
            "source_manifest_sha256": hashes["source-content.sha256"],
            "build_identity_sha256": hashes["clamscan"],
            "config_sha256": hashes["CMakeCache.txt"],
            "database_sha256": hashes["database.ndb"],
        }

    def test_stable_file_preserves_exit_and_identity(self) -> None:
        result = capture.capture(
            self.root, "edge", self.input,
            [sys.executable, "-c", "import sys; sys.exit(2)"],
        )
        self.assertEqual(result, 2)
        before, after = self.sidecars()
        self.assertEqual(before, after)
        identity = json.loads(before)["inputs"]["edge"]
        self.assertEqual(identity["input"], str(self.input))
        self.assertEqual(identity["size"], self.input.stat().st_size)
        self.assertEqual(len(identity["sha256"]), 64)
        with self.assertRaisesRegex(ValueError, "refusing overwrite"):
            capture.capture(self.root, "edge", self.input, [sys.executable, "-V"])

    def test_changed_file_is_rejected_and_both_snapshots_retained(self) -> None:
        command = [
            sys.executable, "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'changed\\n')",
            str(self.input),
        ]
        with self.assertRaisesRegex(ValueError, "changed during"):
            capture.capture(self.root, "edge", self.input, command)
        before, after = self.sidecars()
        self.assertNotEqual(before, after)

    def test_symlinked_input_and_provenance_rejected(self) -> None:
        alias = Path(self.temp.name) / "alias.bin"
        alias.symlink_to(self.input)
        with self.assertRaisesRegex(ValueError, "non-symlinked"):
            capture.capture(self.root, "edge", alias, [sys.executable, "-V"])
        (self.root / "provenance").symlink_to(Path(self.temp.name), target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "provenance directory"):
            capture.capture(self.root, "edge", self.input, [sys.executable, "-V"])

    def test_command_start_failure_keeps_before_and_after(self) -> None:
        code = capture.capture(self.root, "edge", self.input, ["nonexistent-scanner-command-zz"])
        self.assertEqual(code, 125)
        before, after = self.sidecars()
        self.assertEqual(before, after)

    def test_sparse_exact_edge_is_rejected_before_execution(self) -> None:
        with self.input.open("r+b") as stream:
            stream.truncate(capture.EDGE_SIZE)
        with self.assertRaisesRegex(ValueError, "not fully materialized"):
            capture.capture(self.root, "edge", self.input, [sys.executable, "-V"])
        self.assertFalse((self.root / "provenance/direct-inputs-before.json").exists())

    def test_independent_oracle_is_snapshotted_before_command(self) -> None:
        oracle = Path(self.temp.name) / "independent-oracle.json"
        oracle.write_text(json.dumps(self.independent_oracle()), encoding="utf-8")
        command = [
            sys.executable, "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('altered')",
            str(oracle),
        ]
        self.assertEqual(capture.capture(self.root, "edge", self.input, command, oracle), 0)
        snapshot = (self.root / "provenance/direct-oracle.json").read_bytes()
        self.assertNotEqual(snapshot, oracle.read_bytes())
        result = json.loads((self.root / "provenance/direct-command-result.json").read_text())
        self.assertEqual(result["oracle_sha256"], hashlib.sha256(snapshot).hexdigest())
        self.assertTrue(result["input_stable"])

    def test_wrong_independent_oracle_stops_before_scan(self) -> None:
        oracle = Path(self.temp.name) / "wrong-oracle.json"
        expected = self.independent_oracle()
        expected["sha256"] = "0" * 64
        oracle.write_text(json.dumps(expected), encoding="utf-8")
        sentinel = Path(self.temp.name) / "scan-started"
        with self.assertRaisesRegex(ValueError, "does not bind"):
            capture.capture(self.root, "edge", self.input, [
                sys.executable, "-c",
                "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()", str(sentinel),
            ], oracle)
        self.assertFalse(sentinel.exists())
        self.assertFalse((self.root / "provenance/direct-inputs-before.json").exists())

    def test_oracle_with_wrong_build_hash_stops_before_scan(self) -> None:
        oracle = Path(self.temp.name) / "wrong-build-oracle.json"
        expected = self.independent_oracle()
        expected["build_identity_sha256"] = "0" * 64
        oracle.write_text(json.dumps(expected), encoding="utf-8")
        sentinel = Path(self.temp.name) / "scan-started"
        with self.assertRaisesRegex(ValueError, "staged build_identity_sha256"):
            capture.capture(self.root, "edge", self.input, [
                sys.executable, "-c",
                "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()", str(sentinel),
            ], oracle)
        self.assertFalse(sentinel.exists())


if __name__ == "__main__":
    unittest.main()
