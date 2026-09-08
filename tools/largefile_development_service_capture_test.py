#!/usr/bin/env python3
import csv
import tempfile
import unittest
from pathlib import Path

import largefile_acceptance_cases as acceptance_cases
import largefile_development_service_capture as capture


class DevelopmentServiceCaptureTests(unittest.TestCase):
    def test_report_record_uses_embedded_detection_outcome(self):
        with tempfile.TemporaryDirectory(prefix="largefile-service-capture-") as temp:
            root = Path(temp)
            for directory in ("corpus", "logs", "reports", "provenance"):
                (root / directory).mkdir()
            fixture = root / "corpus/detection.bin"
            fixture.write_bytes(b"fixture")
            database = root / "provenance/database.ndb"
            database.write_text("signature\n", encoding="utf-8")
            oracle = root / "provenance/oracle.tsv"
            oracle.write_text("oracle\n", encoding="utf-8")
            config = root / "provenance/clamd.conf"
            config.write_text("config\n", encoding="utf-8")
            source = root / "provenance/source-manifest.txt"
            source.write_text("source\n", encoding="utf-8")
            build = root / "provenance/build-identity.txt"
            build.write_text("build\n", encoding="utf-8")
            daemon_log = root / "logs/clamd.log"
            daemon_log.write_text("PONG\n", encoding="utf-8")
            (root / "logs/scan-detection.log").write_text(
                "protocol_mode=SCANREPORT\n", encoding="utf-8",
            )
            report_path = root / "reports/scan-detection.jsonl"
            report_path.write_text("{}\n", encoding="utf-8")

            report = {
                "status": 0,
                "verdict": 2,
                "completion": "DETECTION_TERMINATED",
                "reason": "Synthetic.Detection",
                "last_alert": "Synthetic.Detection",
                "last_alert_offset": 0,
                **{field: 1 for field in capture.REPORT_NUMERIC_FIELDS},
            }
            manifest = root / "manifest.tsv"
            with manifest.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
                writer.writerow(acceptance_cases.MANIFEST_HEADER)
                writer.writerow(["clamd", "SCANREPORT", "bounded", "clamd/session.c", "work"])
            mapping = root / "map.tsv"
            acceptance_cases.write_map(manifest, mapping)

            record = capture.make_record(
                root, "SCANREPORT", "scan", "detection", fixture, database,
                oracle, config, report, source, build, daemon_log,
            )
            self.assertEqual(record["exit_code"], "1")
            self.assertEqual(record["verdict"], "DETECTED")
            records = root / "provenance/acceptance-cases.tsv"
            with records.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(
                    stream, fieldnames=acceptance_cases.RECORD_HEADER,
                    delimiter="\t", lineterminator="\n",
                )
                writer.writeheader()
                writer.writerow(record)
            self.assertEqual(
                acceptance_cases.validate_records(
                    records, acceptance_cases.validate_map(manifest, mapping),
                    evidence_root=root,
                ),
                1,
            )

    def test_report_modes_have_distinct_capability_bindings(self):
        self.assertEqual(
            set(capture.MODES.values()),
            {"SCANREPORT", "CONTSCANREPORT", "MULTISCANREPORT",
             "ALLMATCHSCANREPORT", "FILDESREPORT", "INSTREAMREPORT"},
        )
        self.assertEqual(
            capture.CLIENT_MODES,
            {"fdpass": "fdpass", "stream": "stream"},
        )

    def test_client_record_uses_client_capability_binding(self):
        with tempfile.TemporaryDirectory(prefix="largefile-client-capture-") as temp:
            root = Path(temp)
            for directory in ("corpus", "logs", "reports", "provenance"):
                (root / directory).mkdir()
            fixture = root / "corpus/detection.bin"
            fixture.write_bytes(b"fixture")
            database = root / "provenance/database.ndb"
            database.write_text("signature\n", encoding="utf-8")
            oracle = root / "provenance/oracle.tsv"
            oracle.write_text("oracle\n", encoding="utf-8")
            config = root / "provenance/clamd.conf"
            config.write_text("config\n", encoding="utf-8")
            source = root / "provenance/source-manifest.txt"
            source.write_text("source\n", encoding="utf-8")
            build = root / "provenance/build-identity.txt"
            build.write_text("build\n", encoding="utf-8")
            daemon_log = root / "logs/clamd.log"
            daemon_log.write_text("PONG\n", encoding="utf-8")
            (root / "logs/client-fdpass-detection.log").write_text(
                "fixture: Synthetic.Detection FOUND\n", encoding="utf-8",
            )
            (root / "reports/client-fdpass-detection.jsonl").write_text(
                "{}\n", encoding="utf-8",
            )
            report = {
                "status": 0,
                "verdict": 2,
                "completion": "DETECTION_TERMINATED",
                "reason": "Synthetic.Detection",
                "last_alert": "Synthetic.Detection",
                "last_alert_offset": 0,
                **{field: 1 for field in capture.REPORT_NUMERIC_FIELDS},
            }
            record = capture.make_record(
                root, "fdpass", "fdpass", "detection", fixture, database,
                oracle, config, report, source, build, daemon_log,
                record_kind="clamdscan", record_id="fdpass",
                artifact_prefix="client-",
            )
            self.assertEqual(record["kind"], "clamdscan")
            self.assertEqual(record["id"], "fdpass")
            self.assertEqual(record["case_id"], "clamdscan:fdpass:detection-edge")
            self.assertEqual(record["artifacts"].split(",")[-2:], [
                "logs/client-fdpass-detection.log",
                "reports/client-fdpass-detection.jsonl",
            ])


if __name__ == "__main__":
    unittest.main(verbosity=2)
