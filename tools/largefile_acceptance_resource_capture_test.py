#!/usr/bin/env python3
import argparse
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import largefile_acceptance_resource_capture as capture


class AcceptanceResourceCaptureTests(unittest.TestCase):
    def test_phase_protocol_tracks_only_ordered_events(self):
        with tempfile.TemporaryDirectory(prefix="largefile-resource-phase-") as directory:
            path = Path(directory) / "phase"
            path.write_text("pcre-start\npost-pcre\ncomplete\n", encoding="utf-8")
            self.assertEqual(capture.phase_state(path), "complete")
            path.write_text("post-pcre\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "without PCRE"):
                capture.phase_state(path)

    def test_phase_protocol_rejects_symlink_replacement(self):
        with tempfile.TemporaryDirectory(prefix="largefile-resource-phase-") as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("pcre-start\n", encoding="utf-8")
            path = root / "phase"
            path.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symlinked"):
                capture.phase_state(path)

    def test_live_sampler_failure_is_fail_closed(self):
        class FakeProcess:
            pid = 4242

            def __init__(self):
                self.alive = True

            def poll(self):
                return None if self.alive else -15

            def wait(self, timeout=None):
                self.alive = False
                return -15

        with tempfile.TemporaryDirectory(prefix="largefile-resource-capture-") as directory:
            root = Path(directory)
            (root / "provenance").mkdir()
            (root / "temporary").mkdir()
            for name in ("source", "build", "config"):
                (root / name).write_text(name, encoding="utf-8")
            args = argparse.Namespace(
                evidence_root=root,
                source_manifest=Path("source"),
                build_identity=Path("build"),
                config=Path("config"),
                temporary_root=Path("temporary"),
                output=Path("provenance/resources.tsv"),
                phase_file=None,
                sample_interval_ms=10,
                kind="parser",
                id="CL_TYPE_DATA",
                case_id="parser:CL_TYPE_DATA:valid-complete",
                command=["synthetic-command"],
            )
            process = FakeProcess()

            def terminate(fake_process):
                fake_process.alive = False

            with mock.patch.object(capture.subprocess, "Popen", return_value=process), \
                    mock.patch.object(capture, "oom_sample", return_value={
                        "oom_events": 0,
                        "oom_kill_events": 0,
                        "oom_cgroup_count": 1,
                        "oom_cgroup_digest": "0" * 64,
                    }), \
                    mock.patch.object(
                        capture, "sample_row",
                        side_effect=capture.CaptureError("synthetic sampler failure"),
                    ), \
                    mock.patch.object(capture, "terminate_child", side_effect=terminate) as stop:
                with self.assertRaisesRegex(ValueError, "while command was alive"):
                    capture.capture(args)
            stop.assert_called_once_with(process)

    def test_temporary_size_is_recursive_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory(prefix="largefile-resource-tree-") as directory:
            root = Path(directory)
            nested = root / "nested"
            nested.mkdir()
            (nested / "payload").write_bytes(b"1234")
            self.assertEqual(capture.temporary_size(root), 4)
            link = root / "link"
            link.symlink_to(nested / "payload")
            with self.assertRaisesRegex(ValueError, "symlink"):
                capture.temporary_size(root)

    def test_path_under_rejects_escape(self):
        with tempfile.TemporaryDirectory(prefix="largefile-resource-path-") as directory:
            root = Path(directory).resolve()
            with self.assertRaisesRegex(ValueError, "escapes"):
                capture.path_under(root, Path("..") / "outside", "artifact")


if __name__ == "__main__":
    unittest.main(verbosity=2)
