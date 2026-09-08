#!/usr/bin/env python3
import csv
import json
from pathlib import Path
import tempfile
import unittest

import largefile_acceptance_cases as acceptance_cases
import largefile_runtime_acceptance_case_producer as producer


class RuntimeAcceptanceCaseProducerTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="largefile-runtime-cases-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.out = self.root / "evidence"
        for directory in (
            "provenance", "corpus", "poc/logs", "poc/reports", "poc/db", "reports",
            "clean-db",
        ):
            (self.out / directory).mkdir(parents=True, exist_ok=True)
        self.manifest = self.root / "manifest.tsv"
        with self.manifest.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
            writer.writerow(acceptance_cases.MANIFEST_HEADER)
            writer.writerow(["clamscan", "file", "bounded", "clamscan/manager.c", "work"])
            writer.writerow(["clamscan", "stdin", "bounded", "clamscan/manager.c", "work"])
        self.mapping = self.root / "map.tsv"
        acceptance_cases.write_map(self.manifest, self.mapping)

        for path, content in {
            "provenance/source-manifest.txt": "source\n",
            "build-identity.txt": (
                "rss_budget_kb=33554432\n"
                "pcre_rss_budget_kb=41943040\n"
                "post_pcre_rss_budget_kb=12582912\n"
                "max_temp_bytes=68719476736\n"
            ),
            "provenance/CMakeCache.txt": "cache\n",
                "provenance/runtime-process-status.tsv": "label\tstatus\n"
                "clamscan:stdin:detection-edge\t1\n"
                "clamscan:file:clean-edge\t0\n"
                "clamscan:stdin:clean-edge\t0\n"
                "clamscan:file:limit-edge\t2\n"
                "clamscan:stdin:limit-edge\t2\n",
            "corpus/manifest.tsv": "file\tmarker\toffset\tsize\tkind\n",
            "poc/db/largefile-poc.ndb": "signature\n",
            "clean-db/clean-no-match.ndb": "Clean.NoMatch:0:*:deadbeef00\n",
        }.items():
            (self.out / path).write_text(content, encoding="utf-8")
        input_path = self.out / "corpus/32g-edge.bin"
        input_path.write_bytes(b"x")
        (self.out / "corpus/32g-head.bin").write_bytes(b"z")
        (self.out / "corpus/32g-plus-one.bin").write_bytes(b"y")

        oracle_header = "label\tkind\tid\tinput\tlog\treport\texpected_size\texpected_exit\texpected_completion\texpected_signature\texpected_offset\n"
        oracle_rows = (
            "clamscan:file:detection-edge\tclamscan\tfile\tcorpus/32g-edge.bin\t"
            "poc/logs/32g-edge.bin.log\tpoc/reports/32g-edge.bin.jsonl\t1\t1\t"
            "DETECTION_TERMINATED\tSynthetic.Detection\t0\n"
            "clamscan:stdin:detection-edge\tclamscan\tstdin\tcorpus/32g-edge.bin\t"
            "32g-edge-stdin.log\treports/32g-edge-stdin.jsonl\t1\t1\t"
            "DETECTION_TERMINATED\tSynthetic.Detection\t0\n"
            "clamscan:file:clean-edge\tclamscan\tfile\tcorpus/32g-head.bin\t"
            "32g-head-clean.log\treports/32g-head-clean.jsonl\t1\t0\t"
            "COMPLETE\t-\t-\n"
            "clamscan:stdin:clean-edge\tclamscan\tstdin\tcorpus/32g-head.bin\t"
            "32g-head-stdin-clean.log\treports/32g-head-stdin-clean.jsonl\t1\t0\t"
            "COMPLETE\t-\t-\n"
            "clamscan:file:limit-edge\tclamscan\tfile\tcorpus/32g-plus-one.bin\t"
            "32g-plus-one-limit.log\treports/32g-plus-one-limit.jsonl\t1\t2\t"
            "LIMIT_INCOMPLETE\t-\t-\n"
            "clamscan:stdin:limit-edge\tclamscan\tstdin\tcorpus/32g-plus-one.bin\t"
            "32g-plus-one-stdin-limit.log\treports/32g-plus-one-stdin-limit.jsonl\t1\t2\t"
            "LIMIT_INCOMPLETE\t-\t-\n"
        )
        (self.out / "provenance/runtime-acceptance-oracle.tsv").write_text(
            oracle_header + oracle_rows, encoding="utf-8")
        poc_header = "\t".join(producer.POC_HEADER) + "\n"
        poc_row = "32g-edge.bin\t0\t1\t1\tyes\t1\tyes\tyes\tyes\t0\tyes\t0\n"
        (self.out / "poc/results.tsv").write_text(poc_header + poc_row, encoding="utf-8")

        report = {
            "version": 1, "status": 1, "verdict": 2,
            "completion": "DETECTION_TERMINATED", "file_type": "CL_TYPE_DATA",
            "root_size": 1, "logical_bytes": 1, "matcher_bytes": 1,
            "contiguous_bytes": 0, "temporary_bytes": 0, "files_scanned": 1,
            "max_recursion_depth": 0, "elapsed_ms": 1, "parser_operations": 1,
            "detector_operations": 1, "skipped_operations": 0,
            "max_scan_size": producer.MAX_SCAN_SIZE_BYTES, "last_alert": "Synthetic.Detection",
            "last_alert_offset": 0, "reason": "Synthetic.Detection",
        }
        for path in (
            "poc/reports/32g-edge.bin.jsonl", "reports/32g-edge-stdin.jsonl",
        ):
            (self.out / path).write_text(json.dumps(report) + "\n", encoding="utf-8")
        for path in ("poc/logs/32g-edge.bin.log", "32g-edge-stdin.log"):
            (self.out / path).write_text(
                "fixture: Synthetic.Detection FOUND\n"
                "signature Synthetic.Detection matched at 0\n", encoding="utf-8")
        limit_report = {
            "version": 1, "status": 24, "verdict": 0,
            "completion": "LIMIT_INCOMPLETE", "file_type": "CL_TYPE_DATA",
            "root_size": 1, "logical_bytes": 0, "matcher_bytes": 0,
            "contiguous_bytes": 0, "temporary_bytes": 0, "files_scanned": 0,
            "max_recursion_depth": 0, "elapsed_ms": 1, "parser_operations": 0,
            "detector_operations": 0, "skipped_operations": 1,
            "max_scan_size": producer.MAX_SCAN_SIZE_BYTES,
            "reason": "Heuristics.Limits.Exceeded.MaxFileSize",
        }
        for path in (
            "reports/32g-plus-one-limit.jsonl",
            "reports/32g-plus-one-stdin-limit.jsonl",
        ):
            (self.out / path).write_text(json.dumps(limit_report) + "\n", encoding="utf-8")
        for path in ("32g-plus-one-limit.log", "32g-plus-one-stdin-limit.log"):
            (self.out / path).write_text("MaxFileSize exceeded\n", encoding="utf-8")
        clean_report = {
            "version": 1, "status": 0, "verdict": 0,
            "completion": "COMPLETE", "file_type": "CL_TYPE_DATA",
            "root_size": 1, "logical_bytes": 1, "matcher_bytes": 1,
            "contiguous_bytes": 1, "temporary_bytes": 0, "files_scanned": 1,
            "max_recursion_depth": 0, "elapsed_ms": 1, "parser_operations": 1,
            "detector_operations": 1, "skipped_operations": 0,
            "max_scan_size": producer.MAX_SCAN_SIZE_BYTES,
            "reason": "complete",
        }
        for path in (
            "reports/32g-head-clean.jsonl",
            "reports/32g-head-stdin-clean.jsonl",
        ):
            (self.out / path).write_text(json.dumps(clean_report) + "\n", encoding="utf-8")
        for path in ("32g-head-clean.log", "32g-head-stdin-clean.log"):
            (self.out / path).write_text("input: OK\n", encoding="utf-8")

    def test_runtime_records_bind_reports_and_poc(self):
        self.assertEqual(producer.produce(self.out, self.manifest, self.mapping), 6)
        mapping = acceptance_cases.validate_map(self.manifest, self.mapping)
        self.assertEqual(
            acceptance_cases.validate_records(
                self.out / "provenance/acceptance-cases.tsv", mapping,
                evidence_root=self.out,
            ),
            6,
        )

    def test_development_records_identify_the_unsanitized_build(self):
        self.assertEqual(
            producer.produce(self.out, self.manifest, self.mapping, sanitizer="development"),
            6,
        )
        with (self.out / "provenance/acceptance-cases.tsv").open(
            newline="", encoding="utf-8",
        ) as stream:
            rows = list(csv.DictReader(stream, delimiter="\t"))
        self.assertEqual({row["sanitizer"] for row in rows}, {"development"})

    def test_runtime_limit_report_cannot_be_relabelled(self):
        report_path = self.out / "reports/32g-plus-one-limit.jsonl"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["reason"] = "Heuristics.Limits.Exceeded.MaxScanSize"
        report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "exact MaxFileSize reason"):
            producer.produce(self.out, self.manifest, self.mapping)

    def test_stdin_limit_report_may_bind_exact_staged_prefix(self):
        report = {
            "version": 1,
            "status": 24,
            "verdict": 0,
            "completion": "LIMIT_INCOMPLETE",
            "root_size": 9,
            "logical_bytes": 0,
            "matcher_bytes": 0,
            "contiguous_bytes": 0,
            "temporary_bytes": 9,
            "files_scanned": 0,
            "max_recursion_depth": 0,
            "elapsed_ms": 0,
            "parser_operations": 0,
            "detector_operations": 0,
            "skipped_operations": 1,
            "max_file_size": 8,
            "max_scan_size": producer.MAX_SCAN_SIZE_BYTES,
            "reason": "Heuristics.Limits.Exceeded.MaxFileSize",
        }
        with self.assertRaisesRegex(ValueError, "expected size/budget"):
            producer.validate_limit(report, "file limit", 54)
        producer.validate_limit(report, "stdin limit", 54, allow_staged_root=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
