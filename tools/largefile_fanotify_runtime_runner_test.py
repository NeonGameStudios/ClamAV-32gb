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
            self.assertIn("MaxScanSize 64G", content)
            self.assertIn("MaxContiguousSize 32G", content)
            self.assertIn("StreamMaxLength 32G", content)
            self.assertIn("OnAccessPrevention yes", content)

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


if __name__ == "__main__":
    raise SystemExit(unittest.main())
