#!/usr/bin/env python3
import csv
import tempfile
import unittest
from pathlib import Path

import largefile_acceptance_cases as acceptance_cases
import largefile_acceptance_resources as resources


class AcceptanceResourceTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="largefile-acceptance-resources-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        (self.root / "provenance").mkdir()
        self.records = self.root / "provenance/acceptance-cases.tsv"
        self.sidecar = self.root / resources.RESOURCE_PATH
        self.case = {
            field: "0" for field in acceptance_cases.RECORD_HEADER
        }
        self.case.update({
            "kind": "parser",
            "id": "CL_TYPE_ZIP",
            "case_id": "parser:CL_TYPE_ZIP:valid-complete",
            "source_manifest_sha256": "a" * 64,
            "build_identity_sha256": "b" * 64,
            "config_sha256": "c" * 64,
            "platform": "Linux-x86_64",
            "fixture_role": "materialized",
            "fixture_sha256": "d" * 64,
            "oracle_sha256": "e" * 64,
            "database_sha256": "f" * 64,
            "exit_code": "0",
            "verdict": "CLEAN",
            "completion": "COMPLETE",
            "reason": "complete",
            "alert_signature": "-",
            "alert_offset": "-",
            "resource_phase": (
                "rss<=33554432;pcre<=41943040;post-pcre<12582912;"
                "temporary<=68719476736"
            ),
            "health": "pass",
            "cleanup": "pass",
            "artifacts": "provenance/acceptance-case-resources.tsv",
        })
        self.resource = {
            field: "0" for field in resources.RESOURCE_HEADER
        }
        self.resource.update({
            "kind": self.case["kind"],
            "id": self.case["id"],
            "case_id": self.case["case_id"],
            "source_manifest_sha256": self.case["source_manifest_sha256"],
            "build_identity_sha256": self.case["build_identity_sha256"],
            "config_sha256": self.case["config_sha256"],
            "platform": self.case["platform"],
            "sample_source": "procfs-process-tree",
            "sample_count": "1",
            "rss_peak_kb": "100",
            "pss_peak_kb": "80",
            "vas_peak_kb": "200",
            "swap_peak_kb": "0",
            "minor_faults_peak": "4",
            "major_faults_peak": "0",
            "read_bytes_peak": "1024",
            "write_bytes_peak": "2048",
            "cancelled_write_bytes_peak": "0",
            "temporary_peak_bytes": "4096",
            "oom_events_peak": "0",
            "oom_kill_events_peak": "0",
            "oom_cgroup_count": "1",
            "oom_cgroup_digest": "1" * 64,
            "pcre_rss_peak_kb": "-",
            "post_pcre_rss_peak_kb": "-",
        })
        self._write_records()
        self._write_resources()

    def _write_records(self):
        with self.records.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream, fieldnames=acceptance_cases.RECORD_HEADER,
                delimiter="\t", lineterminator="\n",
            )
            writer.writeheader()
            writer.writerow(self.case)

    def _write_resources(self):
        with self.sidecar.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream, fieldnames=resources.RESOURCE_HEADER,
                delimiter="\t", lineterminator="\n",
            )
            writer.writeheader()
            writer.writerow(self.resource)

    def test_bind_then_validate(self):
        with self.assertRaisesRegex(ValueError, "does not bind the resource-record hash"):
            resources.validate(self.records, self.root)
        self.assertEqual(resources.bind(self.records, self.root), 1)
        self.assertEqual(resources.validate(self.records, self.root), 1)
        with self.records.open(newline="", encoding="utf-8") as stream:
            row = next(csv.DictReader(stream, delimiter="\t"))
        self.assertIn(f"resource-records={resources.sha256(self.sidecar)}", row["resource_phase"])
        self.assertIn(resources.RESOURCE_PATH, row["artifacts"].split(","))

    def test_swap_is_rejected(self):
        self.resource["swap_peak_kb"] = "1"
        self._write_resources()
        with self.assertRaisesRegex(ValueError, "nonzero swap"):
            resources.validate(self.records, self.root)

    def test_oom_is_rejected(self):
        self.resource["oom_events_peak"] = "1"
        self._write_resources()
        with self.assertRaisesRegex(ValueError, "OOM event"):
            resources.validate(self.records, self.root)

    def test_pss_and_vas_relationships_are_rejected(self):
        self.resource["pss_peak_kb"] = "101"
        self._write_resources()
        with self.assertRaisesRegex(ValueError, "PSS exceeds RSS"):
            resources.validate_resource_rows(
                [self.resource],
                {(self.case["kind"], self.case["id"], self.case["case_id"]): self.case},
            )
        self.resource["pss_peak_kb"] = "80"
        self.resource["vas_peak_kb"] = "99"
        with self.assertRaisesRegex(ValueError, "VAS is below RSS"):
            resources.validate_resource_rows(
                [self.resource],
                {(self.case["kind"], self.case["id"], self.case["case_id"]): self.case},
            )

    def test_pcre_case_requires_phase_peaks(self):
        self.case.update({
            "kind": "matcher",
            "id": "pcre",
            "case_id": "matcher:pcre:exact-tail",
        })
        self.resource.update({
            "kind": "matcher",
            "id": "pcre",
            "case_id": "matcher:pcre:exact-tail",
            "pcre_rss_peak_kb": "200",
            "post_pcre_rss_peak_kb": "100",
        })
        self._write_records()
        self._write_resources()
        self.assertEqual(resources.bind(self.records, self.root), 1)
        self.assertEqual(resources.validate(self.records, self.root), 1)
        self.resource["post_pcre_rss_peak_kb"] = str(resources.POST_PCRE_RSS_KB)
        self._write_resources()
        with self.assertRaisesRegex(ValueError, "post-PCRE RSS"):
            resources.validate(self.records, self.root)

    def test_non_pcre_case_cannot_claim_phase_peaks(self):
        self.resource["pcre_rss_peak_kb"] = "1"
        self._write_resources()
        with self.assertRaisesRegex(ValueError, "non-PCRE"):
            resources.validate(self.records, self.root)

    def test_bind_rejects_duplicate_acceptance_case_rows(self):
        with self.records.open("a", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream, fieldnames=acceptance_cases.RECORD_HEADER,
                delimiter="\t", lineterminator="\n",
            )
            writer.writerow(self.case)
        with self.assertRaisesRegex(ValueError, "acceptance case records duplicate a case"):
            resources.bind(self.records, self.root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
