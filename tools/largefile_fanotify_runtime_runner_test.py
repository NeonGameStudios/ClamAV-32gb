#!/usr/bin/env python3
"""Unit checks for the fail-closed R13 runtime runner helpers."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import largefile_fanotify_runtime_runner as runner


class RuntimeRunnerTests(unittest.TestCase):
    class _ExitedProcess:
        def __init__(self, exit_code):
            self.returncode = exit_code

        def poll(self):
            return self.returncode

    def test_stop_process_allows_graceful_daemon_shutdown(self):
        process = mock.Mock()
        process.poll.side_effect = [None, 0]
        process.returncode = 0

        result = runner.stop_process(process, "clamd")

        process.send_signal.assert_called_once_with(runner.signal.SIGTERM)
        process.wait.assert_called_once_with(timeout=30)
        process.kill.assert_not_called()
        self.assertFalse(result["alive_after_cleanup"])
        self.assertEqual(result["exit_code"], 0)

    def test_failed_runtime_retains_failure_and_cleanup_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="clamav-r13-failure-") as name:
            root = Path(name)
            source = root / "source"
            mount = root / "mount"
            database = root / "db"
            fixture = mount / "fixture.bin"
            for directory in (source, mount, database):
                directory.mkdir()
            fixture.write_bytes(b"fixture")
            clamd = root / "clamd"
            clamonacc = root / "clamonacc"
            clamd.touch()
            clamonacc.touch()
            args = types.SimpleNamespace(
                source_root=source,
                clamd=clamd,
                clamonacc=clamonacc,
                database_directory=database,
                cvd_certs_dir=None,
                mount_path=mount,
                fixture=fixture,
                output_root=root / "output",
                case_name="clean",
                monitoring_only=True,
                actor_uid=65534,
                startup_timeout=1.0,
                actor_timeout=1.0,
                max_file_size="32G",
                max_scan_size="64G",
                max_temporary_size="64G",
                max_scan_time="60000",
                clamd_option=[],
                source_manifest=None,
                build_identity=None,
            )
            processes = [self._ExitedProcess(0), self._ExitedProcess(1)]
            with mock.patch.object(runner.subprocess, "Popen", side_effect=processes), \
                 mock.patch.object(runner, "wait_for_daemon"), \
                 mock.patch.object(runner.time, "sleep"):
                with self.assertRaisesRegex(runner.RunnerError, "clamonacc exited"):
                    runner.run_case(args)
            output = args.output_root
            self.assertTrue((output / "provenance.json").is_file())
            self.assertTrue((output / "health-cleanup.json").is_file())
            self.assertTrue((output / "failure.json").is_file())
            self.assertFalse((output / "result.json").exists())
            failure = json.loads((output / "failure.json").read_text(encoding="utf-8"))
            self.assertIn("clamonacc exited", failure["error"])
            self.assertTrue(failure["cleanup_complete"])

    def test_runner_owned_options_cannot_be_overridden(self):
        with self.assertRaisesRegex(runner.RunnerError, "runner-owned"):
            runner.parse_option("LocalSocket=/tmp/other.sock")

    def test_config_uses_certified_option_ceilings(self):
        with tempfile.TemporaryDirectory(prefix="clamav-r13-runner-") as name:
            root = Path(name)
            for directory in ("db", "tmp", "watch"):
                (root / directory).mkdir()
            args = types.SimpleNamespace(
                max_file_size="32G",
                max_scan_size="64G",
                max_temporary_size="30G",
                max_scan_time="60000",
                clamd_option=[],
            )
            config = root / "clamd.conf"
            runner.write_config(
                config, root / "db", root / "clamd.sock", root / "clamd.pid",
                root / "tmp", root / "watch", True, None, args,
            )
            content = config.read_text(encoding="utf-8")
            self.assertIn("MaxFileSize 32G", content)
            self.assertIn("OnAccessMaxFileSize 32G", content)
            self.assertIn("MaxScanSize 64G", content)
            self.assertIn("MaxContiguousSize 32G", content)
            self.assertIn("StreamMaxLength 32G", content)
            self.assertIn("OnAccessPrevention yes", content)

    def test_alert_exceeds_max_override_replaces_runner_default(self):
        with tempfile.TemporaryDirectory(prefix="clamav-r13-alerts-") as name:
            root = Path(name)
            for directory in ("db", "tmp", "watch"):
                (root / directory).mkdir()
            args = types.SimpleNamespace(
                max_file_size="64M",
                max_scan_size="128M",
                max_temporary_size="64M",
                max_scan_time="60000",
                clamd_option=["AlertExceedsMax=no"],
            )
            config = root / "clamd.conf"
            runner.write_config(
                config, root / "db", root / "clamd.sock", root / "clamd.pid",
                root / "tmp", root / "watch", True, None, args,
            )
            content = config.read_text(encoding="utf-8")
            self.assertIn("AlertExceedsMax no", content)
            self.assertNotIn("AlertExceedsMax yes", content)

    def test_monitoring_report_deadline_tracks_finite_scan_limit(self):
        self.assertEqual(runner.monitoring_report_timeout_seconds("1200000"), 1230.0)
        with self.assertRaisesRegex(runner.RunnerError, "finite positive MaxScanTime"):
            runner.monitoring_report_timeout_seconds("0")
        with self.assertRaisesRegex(runner.RunnerError, "positive integer"):
            runner.monitoring_report_timeout_seconds("unlimited")

    def test_monitoring_waits_for_a_valid_full_fixture_report(self):
        with tempfile.TemporaryDirectory(prefix="clamav-r13-monitor-report-") as name:
            root = Path(name)
            fixture = root / "fixture.bin"
            fixture.write_bytes(b"fixture-bytes")
            report_path = root / "clamonacc-report.jsonl"
            report = {
                "version": 1,
                "clamonacc_event_id": 0,
                "target": str(fixture),
                "completion": "COMPLETE",
                "status": 0,
                "verdict": 0,
                "root_size": fixture.stat().st_size,
                "logical_bytes": fixture.stat().st_size,
                "matcher_bytes": fixture.stat().st_size,
                "contiguous_bytes": 0,
                "temporary_bytes": 0,
                "files_scanned": 1,
                "max_recursion_depth": 0,
                "elapsed_ms": 5,
                "parser_operations": 1,
                "detector_operations": 1,
                "skipped_operations": 0,
                "last_alert": None,
                "last_alert_offset": None,
            }

            def publish_report(_seconds):
                report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")

            with mock.patch.object(runner.time, "sleep", side_effect=publish_report) as sleep:
                observed = runner.wait_for_monitoring_report(
                    report_path, fixture, "clean", runner.sha256(fixture),
                    timeout_seconds=1.0, poll_interval=0.01,
                )
            sleep.assert_called_once()
            self.assertEqual(observed["target"], str(fixture))
            self.assertEqual(observed["root_size"], fixture.stat().st_size)

    def test_monitoring_rejects_a_report_for_the_wrong_case_outcome(self):
        with tempfile.TemporaryDirectory(prefix="clamav-r13-monitor-outcome-") as name:
            root = Path(name)
            fixture = root / "fixture.bin"
            fixture.write_bytes(b"fixture")
            report_path = root / "clamonacc-report.jsonl"
            report_path.write_text(json.dumps({
                "target": str(fixture),
                "clamonacc_event_id": 0,
                "completion": "LIMIT_INCOMPLETE",
            }) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                runner.RunnerError, "expected COMPLETE, got 'LIMIT_INCOMPLETE'"
            ):
                runner.wait_for_monitoring_report(
                    report_path, fixture, "clean", runner.sha256(fixture),
                    timeout_seconds=1.0,
                )

    def test_monitoring_runner_waits_for_scan_report_before_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="clamav-r13-monitor-order-") as name:
            root = Path(name)
            source = root / "source"
            mount = root / "mount"
            database = root / "db"
            fixture = mount / "fixture.bin"
            for directory in (source, mount, database):
                directory.mkdir()
            fixture.write_bytes(b"fixture")
            clamd = root / "clamd"
            clamonacc = root / "clamonacc"
            clamd.touch()
            clamonacc.touch()
            args = types.SimpleNamespace(
                source_root=source,
                clamd=clamd,
                clamonacc=clamonacc,
                database_directory=database,
                cvd_certs_dir=None,
                mount_path=mount,
                fixture=fixture,
                output_root=root / "output",
                case_name="clean",
                monitoring_only=True,
                actor_uid=65534,
                startup_timeout=1.0,
                actor_timeout=1.0,
                max_file_size="32G",
                max_scan_size="64G",
                max_temporary_size="64G",
                max_scan_time="60000",
                clamd_option=[],
                source_manifest=None,
                build_identity=None,
            )
            clamd_process = mock.Mock()
            clamonacc_process = mock.Mock()
            clamd_process.poll.return_value = None
            clamonacc_process.poll.return_value = None
            actor_process = mock.Mock()
            actor_process.wait.return_value = 0
            events = []

            def wait_for_report(path, *_args, **_kwargs):
                events.append("scan-report")
                Path(path).write_text("{}\n", encoding="utf-8")
                return {}

            def stop_process(_process, process_name):
                events.append(f"stop:{process_name}")
                return {
                    "started": True,
                    "alive_after_cleanup": False,
                    "exit_code": 0,
                }

            def start_actor(_fixture, _uid, output):
                Path(output).write_text('{"opened": true}\n', encoding="utf-8")
                return actor_process

            with mock.patch.object(
                runner.subprocess, "Popen", side_effect=[clamd_process, clamonacc_process]
            ), mock.patch.object(runner, "wait_for_daemon"), \
                 mock.patch.object(runner, "start_actor", side_effect=start_actor), \
                 mock.patch.object(runner, "wait_for_monitoring_report", side_effect=wait_for_report) as wait_report, \
                 mock.patch.object(runner, "stop_process", side_effect=stop_process), \
                 mock.patch.object(runner, "ping"), mock.patch.object(runner.time, "sleep"):
                result = runner.run_case(args)

            self.assertEqual(result["mode"], "monitoring-only")
            self.assertEqual(wait_report.call_args.args[4], 90.0)
            self.assertLess(events.index("scan-report"), events.index("stop:clamonacc"))
            health_cleanup = json.loads(
                (args.output_root / "health-cleanup.json").read_text(encoding="utf-8")
            )
            self.assertEqual(health_cleanup["health"]["monitoring_report_state"], "complete")

    def test_report_selection_binds_one_permission_event(self):
        with tempfile.TemporaryDirectory(prefix="clamav-r13-reports-") as name:
            root = Path(name)
            source = root / "reports.jsonl"
            output = root / "selected.jsonl"
            source.write_text(
                "\n".join(json.dumps({"clamonacc_event_id": value}) for value in (2, 7)) + "\n",
                encoding="utf-8",
            )
            runner.select_report(source, 7, output)
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8")),
                {"clamonacc_event_id": 7},
            )

    def test_observer_readiness_requires_a_live_process(self):
        with tempfile.TemporaryDirectory(prefix="clamav-r13-ready-") as name:
            ready = Path(name) / "observer-ready"
            with self.assertRaisesRegex(runner.RunnerError, "exited before readiness"):
                runner.wait_for_file(
                    ready, self._ExitedProcess(1), 0.1, "fanotify observer"
                )


if __name__ == "__main__":
    raise SystemExit(unittest.main())
