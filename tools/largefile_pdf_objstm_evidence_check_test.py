#!/usr/bin/env python3
"""Focused schema controls for PDF object-stream evidence manifests."""

from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
import largefile_pdf_objstm_evidence_check as checker


class PdfEvidenceSchemaTests(unittest.TestCase):
    def assert_rejected(self, body, message):
        with tempfile.TemporaryDirectory(prefix="pdf-evidence-schema-") as directory:
            path = Path(directory) / "manifest.tsv"
            path.write_text(body, encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, message):
                checker.read_tsv(path, ["name", "value"])

    def test_extra_column_is_rejected(self):
        self.assert_rejected(
            "name\tvalue\ncase\tpass\textra\n",
            r"has 3 columns at line 2; expected 2",
        )

    def test_missing_column_is_rejected(self):
        self.assert_rejected(
            "name\tvalue\ncase\n",
            r"has 1 columns at line 2; expected 2",
        )

    def test_empty_field_is_rejected(self):
        self.assert_rejected(
            "name\tvalue\ncase\t\n",
            r"has an empty field at line 2",
        )

    def test_malformed_quoting_is_rejected(self):
        self.assert_rejected(
            "name\tvalue\n\"unterminated\n",
            r"has malformed TSV",
        )

    def test_valid_row_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="pdf-evidence-schema-") as directory:
            path = Path(directory) / "manifest.tsv"
            path.write_text("name\tvalue\ncase\tpass\n", encoding="utf-8")
            self.assertEqual(
                checker.read_tsv(path, ["name", "value"]),
                [{"name": "case", "value": "pass"}],
            )

    def test_symlinked_manifest_path_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="pdf-evidence-schema-") as directory:
            root = Path(directory)
            target = root / "target.bin"
            target.write_bytes(b"fixture")
            (root / "link.bin").symlink_to(target)
            with self.assertRaisesRegex(SystemExit, "manifest path is symlinked"):
                checker.safe_evidence_path(root, "link.bin")


if __name__ == "__main__":
    unittest.main(verbosity=2)
