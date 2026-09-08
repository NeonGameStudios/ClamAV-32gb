#!/usr/bin/env python3
"""Regression controls for contradictory outcomes and exact log signatures."""

import csv
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
import largefile_service_workload_check as checker
import largefile_clamd_report_protocol as protocol


class ResultChecks(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="clamav-results-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.log = self.root / "scan.log"

    def row(self, status=1, completion="DETECTION_TERMINATED", signature="Expected.Marker"):
        return (512, "0" * 64, status, completion, signature,
                "123" if signature != "-" else "-", "CL_TYPE_DATA")

    def oracle(self, row):
        path = self.root / "oracle.tsv"
        with path.open("w", newline="") as stream:
            writer = csv.writer(stream, delimiter="\t")
            writer.writerow(checker.ORACLE_HEADER)
            for role in checker.INPUT_ROLES:
                record = list(row)
                if role == "edge":
                    record[0] = checker.EXACT_EDGE_BYTES
                writer.writerow((role, *record))
        return path

    def report(self, row):
        report = {name: 0 for name in checker.REPORT_FIELDS}
        report.update(version=1, root_size=row[0], file_type=row[6], completion=row[3],
                      max_scan_size=checker.MAX_LOGICAL_BYTES)
        if row[2] == 2:
            report["status"] = 25
        if row[4] != "-":
            report.update(verdict=2, last_alert=row[4], last_alert_offset=int(row[5]))
        return report

    def test_valid_outcomes_remain_accepted(self):
        rows = [self.row(0, "COMPLETE", "-"), self.row()]
        rows += [self.row(2, completion, "-") for completion in (
            "LIMIT_INCOMPLETE", "UNSUPPORTED", "MALFORMED_CONFIRMED",
            "RESOURCE_FAILURE", "APPLICATION_ABORT")]
        for row in rows:
            with self.subTest(row=row):
                self.assertEqual(checker.load_oracle(self.oracle(row))["production"], row)
                checker.validate_report(self.report(row), "valid", row)
                protocol.validate_report(self.report(row), ["production", *map(str, row)], "scan", row[0])

    def test_oracle_cannot_repeat_a_contradiction_to_make_it_valid(self):
        invalid = [
            self.row(0, "DETECTION_TERMINATED", "-"),
            self.row(1, "DETECTION_TERMINATED", "-"),
            self.row(0, "DETECTION_TERMINATED"),
            self.row(2, "DETECTION_TERMINATED"),
            self.row(0, "COMPLETE"),
            self.row(1, "COMPLETE", "-"),
            self.row(2, "COMPLETE", "-"),
            self.row(0, "LIMIT_INCOMPLETE", "-"),
            self.row(1, "UNSUPPORTED"),
            self.row(2, "RESOURCE_FAILURE"),
        ]
        for row in invalid:
            with self.subTest(row=row):
                with self.assertRaisesRegex(RuntimeError, "contradictory"):
                    checker.load_oracle(self.oracle(row))
                # Direct callers must not bypass the contract with an already
                # constructed tuple and a report repeating the same mistake.
                with self.assertRaisesRegex(RuntimeError, "contradictory"):
                    checker.validate_report(self.report(row), "invalid", row)
                with self.assertRaisesRegex(RuntimeError, "contradictory"):
                    protocol.validate_report(self.report(row), ["production", *map(str, row)], "scan", row[0])

    def test_detection_precedence_keeps_earlier_skipped_operations(self):
        row = self.row()
        report = self.report(row)
        report["skipped_operations"] = 3
        checker.validate_report(report, "detected-after-incomplete", row)

    def test_complete_result_cannot_have_skipped_operations(self):
        row = self.row(0, "COMPLETE", "-")
        report = self.report(row)
        report["skipped_operations"] = 1
        with self.assertRaisesRegex(RuntimeError, "complete report"):
            checker.validate_report(report, "incomplete", row)

    def test_detection_report_requires_actual_nonclean_verdict(self):
        row = self.row()
        report = self.report(row)
        report["verdict"] = 0
        with self.assertRaisesRegex(RuntimeError, "non-clean verdict"):
            checker.validate_report(report, "false-clean", row)

    def test_exact_signature_field_formats(self):
        for line in (
            "/path/file: Expected.Marker FOUND\n",
            "stream: Expected.Marker.UNOFFICIAL FOUND\n",
            "fd[12]: Expected.Marker(012345abcdef:512) FOUND\n",
            "/path:with:colons: Expected.Marker FOUND\n",
        ):
            with self.subTest(line=line):
                self.log.write_text(line)
                checker.validate_log(self.log, "exact", self.row(), False)

    def test_signature_substrings_and_unrelated_lines_do_not_count(self):
        for text in (
            "file: NotExpected.MarkerSuffix FOUND\n",
            "file: Expected.MarkerSuffix FOUND\n",
            "file: PrefixExpected.Marker FOUND\n",
            "file: Expected.Marker.UNOFFICIAL.Suffix FOUND\n",
            "/Expected.Marker: Different.Signature FOUND\n",
            "signature Expected.Marker matched at 123\nfile: Different.Signature FOUND\n",
            "Expected.Marker\nfile: FOUND\n",
            "file: Expected.Marker FOUNDISH\n",
            "file: Expected.Marker FOUND extra text\n",
            "Expected.Marker: file: FOUND\n",
        ):
            with self.subTest(text=text):
                self.log.write_text(text)
                with self.assertRaisesRegex(RuntimeError, "expected detection"):
                    checker.validate_log(self.log, "false-match", self.row(), False)

    def test_signature_regex_characters_are_literal(self):
        row = self.row(signature="Sig.A+B")
        self.log.write_text("file: Sig.A+B FOUND\n")
        checker.validate_log(self.log, "literal", row, False)
        self.log.write_text("file: SigXAAAB FOUND\n")
        with self.assertRaisesRegex(RuntimeError, "expected detection"):
            checker.validate_log(self.log, "regex-substitute", row, False)

    def test_explicit_unofficial_suffix_cannot_be_duplicated(self):
        row = self.row(signature="Expected.Marker.UNOFFICIAL")
        self.log.write_text("file: Expected.Marker.UNOFFICIAL FOUND\n")
        checker.validate_log(self.log, "unofficial", row, False)
        self.log.write_text("file: Expected.Marker.UNOFFICIAL.UNOFFICIAL FOUND\n")
        with self.assertRaisesRegex(RuntimeError, "expected detection"):
            checker.validate_log(self.log, "double-suffix", row, False)

    def test_debug_offset_belongs_to_exact_signature_and_number(self):
        for debug in (
            "LibClamAV debug: signature Expected.Marker matched at 123\n",
            "signature Expected.Marker.UNOFFICIAL matched at 123\n",
        ):
            self.log.write_text("file: Expected.Marker FOUND\n" + debug)
            checker.validate_log(self.log, "offset", self.row(), True)
        for debug in (
            "signature Expected.MarkerSuffix matched at 123\n",
            "signature Expected.Marker matched at 1234\n",
            "signature Expected.Marker matched at 123garbage\n",
            "notsignature Expected.Marker matched at 123\n",
        ):
            with self.subTest(debug=debug):
                self.log.write_text("file: Expected.Marker FOUND\n" + debug)
                with self.assertRaisesRegex(RuntimeError, "expected match offset"):
                    checker.validate_log(self.log, "false-offset", self.row(), True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
