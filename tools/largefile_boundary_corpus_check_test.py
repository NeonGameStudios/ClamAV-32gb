#!/usr/bin/env python3
"""Regression tests for the independent sparse-boundary oracle."""

from __future__ import annotations

import csv
from pathlib import Path
import tempfile
import unittest
import sys

sys.dont_write_bytecode = True
import largefile_boundary_corpus_check as checker


class BoundaryCorpusTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="clamav-boundary-oracle-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.rows = (
            ("synthetic.bin", "CLAMAV-SYNTHETIC", 67_108_800, 67_108_864, "sparse-boundary"),
        )
        self.original_rows = checker.ROWS
        checker.ROWS = self.rows
        self.addCleanup(setattr, checker, "ROWS", self.original_rows)

    def write_fixture(self):
        fixture = self.root / "synthetic.bin"
        with fixture.open("wb") as stream:
            stream.truncate(self.rows[0][3])
            stream.seek(self.rows[0][2])
            stream.write(self.rows[0][1].encode("utf-8"))
        with (self.root / "manifest.tsv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
            writer.writerow(checker.MANIFEST_HEADER)
            writer.writerow(self.rows[0])

    def test_valid_manifest_size_and_marker_pass(self):
        self.write_fixture()
        result = checker.validate_corpus(self.root)
        self.assertEqual(result[0]["size"], self.rows[0][3])
        self.assertLess(result[0]["allocated_bytes"], self.rows[0][3])

    def test_manifest_tampering_is_rejected(self):
        self.write_fixture()
        manifest = self.root / "manifest.tsv"
        text = manifest.read_text(encoding="utf-8").replace("67108864", "67108863")
        manifest.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "manifest rows"):
            checker.validate_corpus(self.root)

    def test_marker_tampering_is_rejected(self):
        self.write_fixture()
        with (self.root / "synthetic.bin").open("r+b") as stream:
            stream.seek(self.rows[0][2])
            stream.write(b"BAD")
        with self.assertRaisesRegex(ValueError, "marker window"):
            checker.validate_corpus(self.root)

    def test_extra_manifest_row_is_rejected(self):
        self.write_fixture()
        with (self.root / "manifest.tsv").open("a", encoding="utf-8") as stream:
            stream.write("extra.bin\tX\t0\t64\tsparse-boundary\n")
        with self.assertRaisesRegex(ValueError, "manifest rows"):
            checker.validate_corpus(self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
