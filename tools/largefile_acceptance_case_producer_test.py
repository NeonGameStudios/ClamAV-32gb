#!/usr/bin/env python3
import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import largefile_acceptance_cases as acceptance_cases
import largefile_acceptance_case_producer as producer
import largefile_acceptance_resources as resources


class AcceptanceCaseProducerTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="largefile-case-producer-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.out = self.root / "evidence"
        (self.out / "provenance").mkdir(parents=True)
        (self.out / "logs").mkdir()
        (self.out / "reports").mkdir()
        self.manifest = self.root / "manifest.tsv"
        with self.manifest.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
            writer.writerow(acceptance_cases.MANIFEST_HEADER)
            writer.writerow(["clamscan", "file", "bounded", "clamscan/manager.c", "work"])
        self.mapping = self.root / "map.tsv"
        acceptance_cases.write_map(self.manifest, self.mapping)
        for name, content in {
            "source-manifest.txt": "source\n",
            "service-build-identity.txt": "build\n",
            "CMakeCache.txt": "cache\n",
            "database-manifest-production-before.txt": "db-production\n",
            "database-manifest-edge-before.txt": "db-edge\n",
        }.items():
            (self.out / "provenance" / name).write_text(content, encoding="utf-8")
        (self.out / "service-summary.txt").write_text(
            "service_qualification=pass\n"
            "service_runtime_loader_binding=pass\n"
            "service_temp_budget=pass\n"
            "rss_budget_contract=overall-stricter-than-pcre-phase\n"
            "rss_budget_kb=33554432\n"
            "pcre_rss_budget_kb=41943040\n"
            "post_pcre_rss_budget_kb=12582912\n"
            "service_temp_budget_bytes=68719476736\n", encoding="utf-8")
        oracle_hash = "a" * 64
        (self.out / "provenance/qualification-oracle.tsv").write_text(
            "role\texpected_size\texpected_sha256\texpected_exit\t"
            "expected_completion\texpected_signature\texpected_offset\texpected_type\n"
            + "\n".join([
                f"production\t1\t{oracle_hash}\t1\tDETECTION_TERMINATED\tSynthetic.Detection\t0\tCL_TYPE_DATA",
                f"materialized\t1\t{oracle_hash}\t1\tDETECTION_TERMINATED\tSynthetic.Detection\t0\tCL_TYPE_DATA",
                f"expansion\t1\t{oracle_hash}\t1\tDETECTION_TERMINATED\tSynthetic.Detection\t0\tCL_TYPE_DATA",
                f"edge\t34359738368\t{oracle_hash}\t1\tDETECTION_TERMINATED\tSynthetic.Detection\t0\tCL_TYPE_DATA",
            ]) + "\n", encoding="utf-8")
        self.fixture = self.root / "fixture.bin"
        self.fixture.write_bytes(b"x")
        inputs = {role: {"input": str(self.fixture), "size": 1,
                         "sha256": oracle_hash, "allocated_bytes": 512,
                         "first_hole": None}
                  for role in ("production", "materialized", "expansion", "edge")}
        (self.out / "provenance/service-inputs-before.json").write_text(
            json.dumps({"version": 1, "inputs": inputs}), encoding="utf-8")
        (self.out / "provenance/service-workload-results.tsv").write_text(
            "label\tkind\trole\tinput\tlog\treport\tstatus\tcheck_offset\n"
            f"production-clamscan\tcli\tproduction\t{self.fixture}\tlogs/production.log\t"
            "reports/production.jsonl\t1\tyes\n", encoding="utf-8")
        (self.out / "logs/production.log").write_text(
            "fixture: Synthetic.Detection FOUND\n"
            "signature Synthetic.Detection matched at 0\n", encoding="utf-8")
        report = {
            "version": 1, "status": 0, "verdict": 2,
            "completion": "DETECTION_TERMINATED", "file_type": "CL_TYPE_DATA",
            "root_size": 1, "logical_bytes": 1, "matcher_bytes": 1,
            "contiguous_bytes": 0, "temporary_bytes": 0, "files_scanned": 1,
            "max_recursion_depth": 0, "elapsed_ms": 1, "parser_operations": 1,
            "detector_operations": 1, "skipped_operations": 0,
            "max_scan_size": 68719476736, "last_alert": "Synthetic.Detection",
            "last_alert_offset": 0, "reason": "Synthetic.Detection",
        }
        (self.out / "reports/production.jsonl").write_text(
            json.dumps(report) + "\n", encoding="utf-8")

    def test_producer_binds_real_report_and_hashes(self):
        count = producer.produce(self.out, self.manifest, self.mapping)
        self.assertEqual(count, 1)
        self.assertEqual(
            acceptance_cases.validate_records(
                self.out / "provenance/acceptance-cases.tsv",
                acceptance_cases.validate_map(self.manifest, self.mapping),
                evidence_root=self.out,
            ),
            1,
        )
        with (self.out / "provenance/acceptance-cases.tsv").open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream, delimiter="\t"))
        self.assertEqual(rows[0]["case_id"], "clamscan:file:detection-edge")
        self.assertEqual(rows[0]["fixture_sha256"], "a" * 64)
        self.assertEqual(rows[0]["alert_offset"], "0")
        self.assertEqual(rows[0]["build_identity_sha256"], producer.sha256(self.out / "provenance/service-build-identity.txt"))

        source_manifest = self.out / "provenance/source-manifest.txt"
        source_manifest.write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source_manifest_sha256"):
            acceptance_cases.validate_records(
                self.out / "provenance/acceptance-cases.tsv",
                acceptance_cases.validate_map(self.manifest, self.mapping),
                evidence_root=self.out,
            )

    def test_producer_binds_independent_resource_sidecar_when_requested(self):
        sidecar = self.out / resources.RESOURCE_PATH
        sidecar.parent.mkdir(parents=True, exist_ok=True)
        hashes = {
            "source_manifest_sha256": producer.sha256(self.out / "provenance/source-manifest.txt"),
            "build_identity_sha256": producer.sha256(self.out / "provenance/service-build-identity.txt"),
            "config_sha256": producer.sha256(self.out / "provenance/CMakeCache.txt"),
        }
        row = {field: "0" for field in resources.RESOURCE_HEADER}
        row.update({
            "kind": "clamscan", "id": "file",
            "case_id": "clamscan:file:detection-edge",
            **hashes, "platform": "Linux-x86_64",
            "sample_source": "procfs-process-tree", "sample_count": "1",
            "rss_peak_kb": "100", "pss_peak_kb": "80", "vas_peak_kb": "200",
            "swap_peak_kb": "0", "minor_faults_peak": "1", "major_faults_peak": "0",
            "read_bytes_peak": "1", "write_bytes_peak": "1",
            "cancelled_write_bytes_peak": "0", "temporary_peak_bytes": "0",
            "oom_events_peak": "0", "oom_kill_events_peak": "0",
            "oom_cgroup_count": "1", "oom_cgroup_digest": "1" * 64,
            "pcre_rss_peak_kb": "-", "post_pcre_rss_peak_kb": "-",
        })
        with sidecar.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream, fieldnames=resources.RESOURCE_HEADER,
                delimiter="\t", lineterminator="\n",
            )
            writer.writeheader()
            writer.writerow(row)
        fake_uname = mock.Mock(sysname="Linux", machine="x86_64")
        with mock.patch.object(producer.os, "uname", return_value=fake_uname):
            count = producer.produce(
                self.out, self.manifest, self.mapping,
                resource_sidecar=sidecar,
            )
        self.assertEqual(count, 1)
        self.assertEqual(resources.validate(self.out / "provenance/acceptance-cases.tsv", self.out), 1)

    def test_unmapped_workload_is_not_relabelled(self):
        path = self.out / "provenance/service-workload-results.tsv"
        text = path.read_text(encoding="utf-8").replace("production-clamscan", "production_cvd")
        text = text.replace("production_cvd\tcli\tproduction", "production_cvd\tservice\tproduction")
        text = text.replace("\t1\tyes\n", "\t1\tno\n")
        path.write_text(text, encoding="utf-8")
        self.assertEqual(producer.produce(self.out, self.manifest, self.mapping), 0)

    def test_unknown_workload_label_is_rejected(self):
        path = self.out / "provenance/service-workload-results.tsv"
        text = path.read_text(encoding="utf-8").replace(
            "production-clamscan", "unreviewed-workload"
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unknown workload label"):
            producer.produce(self.out, self.manifest, self.mapping)

    def test_duplicate_service_input_json_keys_are_rejected(self):
        path = self.out / "provenance/service-inputs-before.json"
        path.write_text('{"version": 1, "version": 1, "inputs": {}}\n', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: version"):
            producer.produce(self.out, self.manifest, self.mapping)

    def test_workload_schema_rejects_rows_with_wrong_column_count(self):
        path = self.out / "provenance/service-workload-results.tsv"
        path.write_text(path.read_text(encoding="utf-8").rstrip("\n") + "\textra\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "columns at line 2"):
            producer.produce(self.out, self.manifest, self.mapping)

    def test_workload_paths_are_admitted_before_any_file_is_read(self):
        outside_report = self.root / "outside.jsonl"
        outside_report.write_text("not a report\n", encoding="utf-8")
        path = self.out / "provenance/service-workload-results.tsv"
        path.write_text(
            "label\tkind\trole\tinput\tlog\treport\tstatus\tcheck_offset\n"
            f"production-clamscan\tcli\tproduction\t{self.fixture}\t"
            f"logs/production.log\t../outside.jsonl\t1\tyes\n",
            encoding="utf-8",
        )
        with mock.patch.object(
            producer.workload_check,
            "load_report",
            side_effect=AssertionError("outside report was opened"),
        ):
            with self.assertRaisesRegex(ValueError, "escapes the service evidence directory"):
                producer.produce(self.out, self.manifest, self.mapping)

    def test_symlinked_workload_paths_are_rejected_before_any_file_is_read(self):
        link = self.out / "reports/production-link.jsonl"
        link.symlink_to(self.out / "reports/production.jsonl")
        path = self.out / "provenance/service-workload-results.tsv"
        path.write_text(
            "label\tkind\trole\tinput\tlog\treport\tstatus\tcheck_offset\n"
            f"production-clamscan\tcli\tproduction\t{self.fixture}\t"
            f"logs/production.log\treports/production-link.jsonl\t1\tyes\n",
            encoding="utf-8",
        )
        with mock.patch.object(
            producer.workload_check,
            "load_report",
            side_effect=AssertionError("symlinked report was opened"),
        ):
            with self.assertRaisesRegex(ValueError, "is symlinked"):
                producer.produce(self.out, self.manifest, self.mapping)

    def test_workload_matrix_rejects_special_kind_before_report_read(self):
        path = self.out / "provenance/service-workload-results.tsv"
        path.write_text(
            "label\tkind\trole\tinput\tlog\treport\tstatus\tcheck_offset\n"
            f"production-clamscan\tlegacy\tproduction\t{self.fixture}\t"
            "logs/production.log\treports/production.jsonl\t1\tyes\n",
            encoding="utf-8",
        )
        with mock.patch.object(
            producer.workload_check,
            "load_report",
            side_effect=AssertionError("special workload report was opened"),
        ):
            with self.assertRaisesRegex(ValueError, "reviewed matrix"):
                producer.produce(self.out, self.manifest, self.mapping)

    def test_report_transport_success_binds_embedded_detection_exit(self):
        with self.manifest.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
            writer.writerow(acceptance_cases.MANIFEST_HEADER)
            writer.writerow(["clamd", "SCANREPORT", "bounded", "clamd/session.c", "work"])
        acceptance_cases.write_map(self.manifest, self.mapping)
        path = self.out / "provenance/service-workload-results.tsv"
        path.write_text(
            "label\tkind\trole\tinput\tlog\treport\tstatus\tcheck_offset\n"
            f"production_cvd_scanreport\treport\tproduction\t{self.fixture}\t"
            "logs/production.log\treports/production.jsonl\t0\tno\n",
            encoding="utf-8",
        )
        count = producer.produce(self.out, self.manifest, self.mapping)
        self.assertEqual(count, 1)
        with (self.out / "provenance/acceptance-cases.tsv").open(
            newline="", encoding="utf-8",
        ) as stream:
            row = next(csv.DictReader(stream, delimiter="\t"))
        self.assertEqual(row["completion"], "DETECTION_TERMINATED")
        self.assertEqual(row["exit_code"], "1")
        self.assertEqual(row["case_id"], "clamd:SCANREPORT:detection-edge")
        acceptance_cases.validate_records(
            self.out / "provenance/acceptance-cases.tsv",
            acceptance_cases.validate_map(self.manifest, self.mapping),
            evidence_root=self.out,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
