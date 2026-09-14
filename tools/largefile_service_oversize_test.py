#!/usr/bin/env python3
"""Focused negative controls for the sparse oversized service probe."""

import json
import os
import re
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import largefile_service_oversize as probe


def report(alert=True):
    value = {"version": 1, "root_size": probe.OVERSIZE_BYTES,
             "max_file_size": probe.MAX_FILE_SIZE, "max_scan_size": 68719476736,
             "temporary_bytes": 0, "matcher_bytes": 0, "logical_bytes": 0,
             "parser_operations": 0, "skipped_operations": 1,
             "reason": probe.LIMIT_ALERT,
             "status": 0 if alert else probe.CL_EMAXSIZE,
             "verdict": 3 if alert else 0,
             "completion": "DETECTION_TERMINATED" if alert else "LIMIT_INCOMPLETE"}
    if alert:
        value["last_alert"] = probe.LIMIT_ALERT
    return value


def evidence():
    metadata = {"size_bytes": probe.OVERSIZE_BYTES, "allocated_bytes": 0,
                "device": 1, "inode": 2, "mtime_ns": 3, "ctime_ns": 4,
                "regular_file": True}
    return {"schema": probe.SCHEMA, "command": "FILDESREPORT",
            "purpose": "sparse-size-limit-rejection-only", "fixture_before": metadata,
            "fixture_after": dict(metadata), "fixture_removed": True,
            "daemon_ping_before": "PONG", "daemon_ping_after": "PONG", "report": report()}


def both_mode_evidence():
    alert_off = evidence()
    alert_off["alert_mode"] = "off"
    alert_off["report"] = report(False)
    alert_on = evidence()
    alert_on["alert_mode"] = "on"
    return probe.combine_evidence(alert_off, alert_on)


class OversizeTests(unittest.TestCase):
    def test_fixed_production_boundary(self):
        self.assertEqual(probe.MAX_FILE_SIZE, 32 * 1024**3)
        self.assertEqual(probe.OVERSIZE_BYTES, 32 * 1024**3 + 1)

    def test_status_constant_matches_public_header(self):
        root = Path(os.environ.get("CLAMAV_SOURCE_ROOT", Path(__file__).resolve().parents[1]))
        header = root / "libclamav" / "clamav.h"
        if not header.is_file():
            self.skipTest("source header unavailable; set CLAMAV_SOURCE_ROOT")
        declaration = re.search(r"typedef enum cl_error_t\s*\{(.*?)\}\s*cl_error_t;",
                                header.read_text(), re.S)
        self.assertIsNotNone(declaration)
        body = re.sub(r"/\*.*?\*/", "", declaration.group(1), flags=re.S)
        value = -1
        values = {}
        for item in body.split(","):
            if not item.strip():
                continue
            parts = item.strip().split("=")
            value = int(parts[1].strip(), 0) if len(parts) == 2 else value + 1
            values[parts[0].strip()] = value
        self.assertEqual(probe.CL_EMAXSIZE, values["CL_EMAXSIZE"])
        self.assertEqual(values["CL_SUCCESS"], 0)
        self.assertEqual(values["CL_VIRUS"], 1)
        self.assertNotEqual(probe.CL_EMAXSIZE, values["CL_EMAXFILES"])

    def test_both_size_rejection_contracts(self):
        probe.validate_report(report())
        probe.validate_report(report(False))
        value = report()
        value["status"] = 1
        probe.validate_report(value)

    def test_both_alert_modes_bind_to_their_expected_completion(self):
        bundle = both_mode_evidence()
        self.assertEqual(bundle["schema"], probe.BUNDLE_SCHEMA)
        probe.validate_evidence(json.loads(json.dumps(bundle)))
        bundle["alert_off"]["report"]["completion"] = "DETECTION_TERMINATED"
        with self.assertRaises(ValueError):
            probe.validate_bundle(bundle)

    def test_reject_bad_report_fields(self):
        cases = {"root_size": probe.MAX_FILE_SIZE, "max_file_size": probe.MAX_FILE_SIZE - 1,
                 "max_scan_size": probe.MAX_FILE_SIZE, "temporary_bytes": 1,
                 "matcher_bytes": 1, "logical_bytes": 1, "parser_operations": 1, "skipped_operations": 0, "reason": "MaxFileSize exceeded",
                 "last_alert": "NotHeuristics.Limits.Exceeded.MaxFileSizeSuffix",
                 "status": 25, "verdict": 0, "completion": "COMPLETE", "version": True}
        for key, value in cases.items():
            with self.subTest(field=key):
                candidate = report()
                candidate[key] = value
                with self.assertRaises(ValueError):
                    probe.validate_report(candidate)

    def test_reject_other_limits_errors_and_generic_found(self):
        for alert in ("Heuristics.Limits.Exceeded.MaxScanSize", "Heuristics.Limits.Exceeded.MaxFiles",
                      "Heuristics.Limits.Exceeded.MaxFileSize.UNOFFICIAL", "FOUND", "Malware"):
            candidate = report()
            candidate.update(reason=alert, last_alert=alert)
            with self.subTest(alert=alert), self.assertRaises(ValueError):
                probe.validate_report(candidate)
        for status in (0, 1, 21, 25, 26, 35, True):
            candidate = report(False)
            candidate["status"] = status
            with self.subTest(status=status), self.assertRaises(ValueError):
                probe.validate_report(candidate)

    def test_reject_numeric_strings_bools_and_negatives(self):
        for key in ("status", "verdict", "root_size", "max_file_size", "max_scan_size",
                    "temporary_bytes", "matcher_bytes", "logical_bytes", "parser_operations", "skipped_operations"):
            for invalid in (False, "0", -1, None):
                candidate = report()
                candidate[key] = invalid
                with self.subTest(field=key, value=invalid), self.assertRaises(ValueError):
                    probe.validate_report(candidate)

    def test_reject_missing_admission_counters(self):
        for key in ("logical_bytes", "parser_operations"):
            candidate = report()
            del candidate[key]
            with self.subTest(field=key), self.assertRaises(ValueError):
                probe.validate_report(candidate)

    def test_incomplete_cannot_carry_alert(self):
        for key, value in (("last_alert", probe.LIMIT_ALERT), ("last_alert_offset", 0), ("verdict", 3)):
            candidate = report(False)
            candidate[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                probe.validate_report(candidate)

    def test_saved_evidence_does_not_need_retained_fixture(self):
        probe.validate_evidence(json.loads(json.dumps(evidence())))

    def test_reject_evidence_without_health_cleanup_or_separate_purpose(self):
        for key, invalid in (("daemon_ping_before", ""), ("daemon_ping_after", "ERROR"),
                             ("fixture_removed", False), ("fixture_removed", 1),
                             ("purpose", "fully-materialized"), ("command", "FILDES"),
                             ("schema", "unknown"), ("fixture_before", None)):
            candidate = evidence()
            candidate[key] = invalid
            with self.subTest(field=key), self.assertRaises(ValueError):
                probe.validate_evidence(candidate)

    def test_reject_missing_or_altered_fixture_metadata(self):
        for key in evidence()["fixture_before"]:
            candidate = evidence()
            del candidate["fixture_before"][key]
            with self.subTest(field=key), self.assertRaises(ValueError):
                probe.validate_evidence(candidate)
        for key in ("size_bytes", "allocated_bytes", "device", "inode", "mtime_ns", "ctime_ns"):
            candidate = evidence()
            candidate["fixture_after"][key] += 1
            with self.subTest(field=key), self.assertRaises(ValueError):
                probe.validate_evidence(candidate)

    def test_reject_materialized_or_unmeasured_allocation(self):
        for allocation in (probe.OVERSIZE_BYTES, None, False, -1):
            candidate = evidence()
            for name in ("fixture_before", "fixture_after"):
                candidate[name]["allocated_bytes"] = allocation
            with self.subTest(allocation=allocation), self.assertRaises(ValueError):
                probe.validate_evidence(candidate)

    def test_probe_passes_real_exact_size_descriptor_and_removes_fixture(self):
        # This creates the actual 32 GiB + 1 sparse fixture, but mocks the daemon;
        # it neither reads its payload nor claims runtime rejection evidence.
        seen = []
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection

        def receive_descriptor(buffers, ancillary):
            fd = struct.unpack("i", ancillary[0][2])[0]
            seen.append(os.fstat(fd).st_size)
            self.assertEqual(buffers, [b"\x00"])
            return 1

        connection.sendmsg.side_effect = receive_descriptor
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(probe, "ping", return_value="PONG") as health, \
                 mock.patch.object(probe, "connect", return_value=connection), \
                 mock.patch.object(probe, "receive_report", return_value=report()):
                result = probe.probe("test.sock", directory)
            self.assertEqual(list(Path(directory).iterdir()), [])
            self.assertEqual(health.call_count, 2)
        self.assertEqual(seen, [34359738369])
        connection.sendall.assert_called_once_with(b"zFILDESREPORT\x00")
        probe.validate_evidence(result)

    def test_probe_binds_alert_mode(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(probe, "ping", return_value="PONG"), \
                 mock.patch.object(probe, "connect", return_value=connection), \
                 mock.patch.object(probe, "receive_report", return_value=report(False)):
                result = probe.probe("test.sock", directory, 7, "off")
        self.assertEqual(result["alert_mode"], "off")
        probe.validate_evidence(result, "off")

    def test_shared_wire_frame_decoder_with_fragmented_response(self):
        payload = json.dumps(report()).encode("utf-8")
        frame = bytearray(struct.pack("!I", len(payload)) + payload + b"\x00" * 4)
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection

        def receive(length):
            amount = min(length, 3, len(frame))
            result = bytes(frame[:amount])
            del frame[:amount]
            return result

        connection.recv.side_effect = receive
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(probe, "ping", return_value="PONG"), \
                 mock.patch.object(probe, "connect", return_value=connection):
                result = probe.probe("test.sock", directory)
            self.assertEqual(list(Path(directory).iterdir()), [])
        self.assertEqual(frame, b"")
        probe.validate_evidence(result)

    def test_cleanup_after_protocol_failure(self):
        connection = mock.MagicMock()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(probe, "ping", return_value="PONG"), \
                 mock.patch.object(probe, "connect", return_value=connection), \
                 mock.patch.object(probe, "receive_report", side_effect=RuntimeError("broken frame")):
                with self.assertRaisesRegex(RuntimeError, "broken frame"):
                    probe.probe("test.sock", directory)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_bad_report_still_gets_health_check_and_cleanup(self):
        connection = mock.MagicMock()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(probe, "ping", return_value="PONG") as health, \
                 mock.patch.object(probe, "connect", return_value=connection), \
                 mock.patch.object(probe, "receive_report", return_value={}):
                with self.assertRaises(ValueError):
                    probe.probe("test.sock", directory)
            self.assertEqual(health.call_count, 2)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cli_publishes_validated_json(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "oversize.json"
            with mock.patch.object(probe, "probe", return_value=evidence()) as run:
                self.assertEqual(probe.main(["test.sock", str(output), directory, "7"]), 0)
            run.assert_called_once_with("test.sock", directory, 7)
            probe.validate_evidence(json.loads(output.read_text()))
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    def test_cli_combines_alert_on_and_off_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            off = root / "off.json"
            on = root / "on.json"
            output = root / "both.json"
            bundle = both_mode_evidence()
            off.write_text(json.dumps(bundle["alert_off"]))
            on.write_text(json.dumps(bundle["alert_on"]))
            self.assertEqual(probe.main(["--combine", str(output), str(off), str(on)]), 0)
            probe.validate_evidence(json.loads(output.read_text()))

    def test_cli_combine_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            off = root / "off.json"
            on = root / "on.json"
            off.write_text('{"schema": "x", "schema": "y"}\n', encoding="utf-8")
            on.write_text(json.dumps(both_mode_evidence()["alert_on"]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key: schema"):
                probe.main(["--combine", str(root / "both.json"), str(off), str(on)])

    def test_cli_has_no_fixture_size_override(self):
        self.assertEqual(probe.main(["socket", "output", "tmp", "60", "1048577"]), 2)

    def test_invalid_timeout(self):
        for invalid in (0, -1, True, "60"):
            with self.subTest(timeout=invalid), self.assertRaises(ValueError):
                probe.probe("test.sock", "unused", invalid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
