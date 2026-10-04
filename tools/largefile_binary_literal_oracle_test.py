#!/usr/bin/env python3
"""Bounded raw-fixture oracle regression tests; no large fixture required."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import largefile_binary_literal_oracle as oracle


class BinaryLiteralOracleTests(unittest.TestCase):
    def write_input(self, root: Path, payload: bytes) -> tuple[Path, str]:
        path = root / "input.bin"
        path.write_bytes(payload)
        return path, hashlib.sha256(payload).hexdigest()

    def test_boundary_marker_and_absent_control(self) -> None:
        payload = b"Z" * 4093 + b"ABCDEF" + b"Z" * 5000
        with tempfile.TemporaryDirectory() as directory:
            path, digest = self.write_input(Path(directory), payload)
            result = oracle.verify(
                path,
                len(payload),
                digest,
                [("edge", b"ABCDEF", 4093), ("clean", b"NOT-HERE", None)],
                chunk_bytes=4096,
            )
        self.assertEqual(result["bytes_read"], len(payload))
        self.assertEqual(result["sha256"], digest)
        self.assertEqual(result["cases"]["edge"]["count"], 1)
        self.assertEqual(result["cases"]["edge"]["first_offset"], 4093)
        self.assertEqual(result["cases"]["clean"]["count"], 0)
        self.assertTrue(result["stable_metadata"])
        self.assertIsNone(result["first_hole_offset"])

    def test_repeated_marker_fails_closed(self) -> None:
        payload = b"ababa" + b"Z" * 5000
        with tempfile.TemporaryDirectory() as directory:
            path, digest = self.write_input(Path(directory), payload)
            with self.assertRaisesRegex(ValueError, "unexpected offset"):
                oracle.verify(path, len(payload), digest, [("edge", b"aba", 0)],
                              chunk_bytes=4096)

    def test_wrong_size_hash_and_absence_fail_closed(self) -> None:
        payload = b"ABCDEF" + b"Z" * 5000
        with tempfile.TemporaryDirectory() as directory:
            path, digest = self.write_input(Path(directory), payload)
            with self.assertRaisesRegex(ValueError, "expected size"):
                oracle.verify(path, len(payload) + 1, digest,
                              [("edge", b"ABCDEF", 0)])
            with self.assertRaisesRegex(ValueError, "SHA-256 differs"):
                oracle.verify(path, len(payload), "0" * 64,
                              [("edge", b"ABCDEF", 0)])
            with self.assertRaisesRegex(ValueError, "unexpected offset"):
                oracle.verify(path, len(payload), digest,
                              [("clean", b"ABCDEF", None)])

    def test_symlink_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, digest = self.write_input(root, b"ABCDEF")
            link = root / "link.bin"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                oracle.verify(link, 6, digest, [("edge", b"ABCDEF", 0)])

    def test_materialized_check_rejects_reported_hole(self) -> None:
        payload = os.urandom(8192)
        with tempfile.TemporaryDirectory() as directory:
            path, digest = self.write_input(Path(directory), payload)
            real_lseek = os.lseek

            def fake_lseek(fd: int, offset: int, whence: int) -> int:
                if whence == os.SEEK_HOLE:
                    return 1024
                return real_lseek(fd, offset, whence)

            with patch.object(oracle.os, "lseek", side_effect=fake_lseek):
                with self.assertRaisesRegex(ValueError, "hole at offset 1024"):
                    oracle.verify(path, len(payload), digest,
                                  [("clean", b"NOT-HERE", None)],
                                  require_materialized=True)

    def test_materialized_check_records_first_hole_at_eof(self) -> None:
        payload = os.urandom(8192)
        with tempfile.TemporaryDirectory() as directory:
            path, digest = self.write_input(Path(directory), payload)
            real_lseek = os.lseek

            def fake_lseek(fd: int, offset: int, whence: int) -> int:
                if whence == os.SEEK_HOLE:
                    return len(payload)
                return real_lseek(fd, offset, whence)

            with patch.object(oracle.os, "lseek", side_effect=fake_lseek):
                result = oracle.verify(path, len(payload), digest,
                                       [("clean", b"NOT-HERE", None)],
                                       require_materialized=True)
        self.assertEqual(result["first_hole_offset"], len(payload))

    def test_cli_json_and_errors(self) -> None:
        payload = b"Z" * 4093 + b"ABCDEF" + b"Z" * 5000
        with tempfile.TemporaryDirectory() as directory:
            path, digest = self.write_input(Path(directory), payload)
            args = [
                "--file", str(path), "--expected-size", str(len(payload)),
                "--expected-sha256", digest,
                "--case", "edge:414243444546:4093",
                "--case", "clean:4e4f542d48455245:absent",
            ]
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(oracle.main(args), 0)
            self.assertEqual(json.loads(stdout.getvalue())["cases"]["edge"]["count"], 1)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(oracle.main(args[:-1] + ["clean:414243444546:absent"]), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("oracle failed", stderr.getvalue())

    def test_invalid_case_and_duplicate_names(self) -> None:
        for value in ("", "edge", "edge:0:1", "EDGE:41:0", "edge:41:-1",
                      "edge:41:1.5", "edge:gg:0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                oracle.parse_case(value)
        payload = b"A" * 5000
        with tempfile.TemporaryDirectory() as directory:
            path, digest = self.write_input(Path(directory), payload)
            with self.assertRaisesRegex(ValueError, "must be unique"):
                oracle.verify(path, len(payload), digest,
                              [("same", b"B", None), ("same", b"C", None)])


if __name__ == "__main__":
    unittest.main()
