#!/usr/bin/env python3
import argparse
import sys
import tempfile
import unittest
from pathlib import Path
from io import StringIO
from unittest import mock

import largefile_acceptance_resource_capture as capture


class AcceptanceResourceCaptureTests(unittest.TestCase):
    def test_phase_protocol_tracks_only_ordered_events(self):
        with tempfile.TemporaryDirectory(prefix="largefile-resource-phase-") as directory:
            path = Path(directory) / "phase"
            path.write_text("pcre-start\npost-pcre\ncomplete\n", encoding="utf-8")
            self.assertEqual(capture.phase_state(path), "complete")
            path.write_text("pcre-start\npost-pcre\ndeep-parse\n", encoding="utf-8")
            self.assertEqual(capture.phase_state(path), "deep-parse")
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

    def test_append_phase_event_writes_terminal_event(self):
        with tempfile.TemporaryDirectory(prefix="largefile-resource-phase-") as directory:
            path = Path(directory) / "phase"
            path.write_text("pcre-start\npost-pcre\n", encoding="utf-8")
            capture.append_phase_event(path, "complete")
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                "pcre-start\npost-pcre\ncomplete\n",
            )
            self.assertEqual(capture.phase_state(path), "complete")

    def test_append_phase_event_rejects_symlink(self):
        with tempfile.TemporaryDirectory(prefix="largefile-resource-phase-") as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("post-pcre\n", encoding="utf-8")
            path = root / "phase"
            path.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symlinked"):
                capture.append_phase_event(path, "complete")

    def test_process_log_rejects_symlink(self):
        with tempfile.TemporaryDirectory(prefix="largefile-resource-log-") as directory:
            root = Path(directory)
            (root / "provenance").mkdir()
            (root / "temporary").mkdir()
            for name in ("source", "build", "config"):
                (root / name).write_text(name, encoding="utf-8")
            target = root / "provenance/target.log"
            target.write_text("", encoding="utf-8")
            (root / "provenance/process.log").symlink_to(target)
            args = argparse.Namespace(
                evidence_root=root,
                source_manifest=Path("source"),
                build_identity=Path("build"),
                config=Path("config"),
                temporary_root=Path("temporary"),
                output=Path("provenance/resources.tsv"),
                phase_file=None,
                process_log=Path("provenance/process.log"),
                sample_interval_ms=10,
                kind="parser",
                id="CL_TYPE_DATA",
                case_id="parser:CL_TYPE_DATA:valid-complete",
                command=["synthetic-command"],
            )
            with mock.patch.object(capture.subprocess, "Popen") as start:
                with self.assertRaisesRegex(ValueError, "process log is symlinked"):
                    capture.capture(args)
            start.assert_not_called()

    def test_sample_log_rejects_symlink(self):
        with tempfile.TemporaryDirectory(prefix="largefile-resource-samples-") as directory:
            root = Path(directory)
            (root / "provenance").mkdir()
            (root / "temporary").mkdir()
            for name in ("source", "build", "config"):
                (root / name).write_text(name, encoding="utf-8")
            target = root / "provenance/target.tsv"
            target.write_text("", encoding="utf-8")
            (root / "provenance/samples.tsv").symlink_to(target)
            args = argparse.Namespace(
                evidence_root=root,
                source_manifest=Path("source"),
                build_identity=Path("build"),
                config=Path("config"),
                temporary_root=Path("temporary"),
                output=Path("provenance/resources.tsv"),
                phase_file=None,
                process_log=None,
                sample_log=Path("provenance/samples.tsv"),
                sample_interval_ms=10,
                kind="parser",
                id="CL_TYPE_DATA",
                case_id="parser:CL_TYPE_DATA:valid-complete",
                command=["synthetic-command"],
            )
            with mock.patch.object(capture.subprocess, "Popen") as start:
                with self.assertRaisesRegex(ValueError, "sample trace is symlinked"):
                    capture.capture(args)
            start.assert_not_called()

    def test_sample_trace_is_timestamped_and_root_bounded(self):
        stream = StringIO()
        with mock.patch.object(capture.time, "time_ns", return_value=123456789):
            capture.append_sample_trace(stream, 1, "pcre", 7, 11, 2)
        self.assertEqual(stream.getvalue(), "1\t123456789\tpcre\t7\t11\t2\n")

    def test_complete_does_not_fabricate_deep_parse_sample(self):
        with tempfile.TemporaryDirectory(prefix="largefile-resource-complete-") as directory:
            root = Path(directory)
            temporary = root / "temporary"
            temporary.mkdir()
            phase = root / "phase"
            phase.write_text("pcre-start\npost-pcre\ncomplete\n", encoding="utf-8")
            current = {
                "sample_count": 0,
                **{field: 0 for field in capture.METRIC_FIELDS},
                "temporary_peak_bytes": 0,
                "oom_events_peak": 0,
                "oom_kill_events_peak": 0,
                "oom_cgroup_count": 0,
                "oom_cgroup_digest": "",
            }
            metric = {
                "rss_kb": 7,
                "pss_kb": 7,
                "vas_kb": 7,
                "swap_kb": 0,
                "minor_faults": 0,
                "major_faults": 0,
                "read_bytes": 0,
                "write_bytes": 0,
                "cancelled_write_bytes": 0,
                "root_rss_kb": 7,
                "process_count": 1,
            }
            oom = {
                "oom_events": 0,
                "oom_kill_events": 0,
                "oom_cgroup_count": 1,
                "oom_cgroup_digest": "0" * 64,
            }
            stream = StringIO()
            with mock.patch.object(capture, "metric_sample", return_value=metric), \
                    mock.patch.object(capture, "oom_sample", return_value=oom):
                capture.sample_row(
                    1, temporary, phase,
                    oom.copy(), current,
                    {"pcre_rss_peak_kb": None, "post_pcre_rss_peak_kb": None},
                    stream,
                )
            self.assertEqual(stream.getvalue(), "")

    def test_phase_watcher_retains_fast_boundary_events(self):
        metric = {
            "rss_kb": 10,
            "pss_kb": 10,
            "vas_kb": 10,
            "swap_kb": 0,
            "minor_faults": 0,
            "major_faults": 0,
            "read_bytes": 0,
            "write_bytes": 0,
            "cancelled_write_bytes": 0,
            "root_rss_kb": 10,
            "process_count": 1,
        }
        oom = {
            "oom_events": 0,
            "oom_kill_events": 0,
            "oom_cgroup_count": 1,
            "oom_cgroup_digest": "0" * 64,
        }
        script = (
            "import os, time\n"
            "phase = os.environ['CLAMAV_LARGEFILE_RESOURCE_PHASE_FILE']\n"
            "for event in ('pcre-start', 'post-pcre', 'deep-parse'):\n"
            "    with open(phase, 'a', encoding='ascii') as stream:\n"
            "        stream.write(event + '\\n')\n"
            "        stream.flush()\n"
            "    time.sleep(0.05)\n"
        )
        with tempfile.TemporaryDirectory(prefix="largefile-phase-watch-") as directory:
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
                phase_file=Path("provenance/phase"),
                process_log=None,
                sample_log=Path("provenance/samples.tsv"),
                sample_interval_ms=100,
                kind="matcher",
                id="pcre",
                case_id="matcher:pcre:phase-watch",
                command=[sys.executable, "-c", script],
            )
            with mock.patch.object(capture, "metric_sample", return_value=metric), \
                    mock.patch.object(capture, "oom_sample", return_value=oom), \
                    mock.patch.object(
                        capture.os, "uname",
                        return_value=mock.Mock(sysname="Linux", machine="x86_64"),
                    ):
                self.assertEqual(capture.capture(args), 0)
            trace = (root / "provenance/samples.tsv").read_text(encoding="utf-8")
            self.assertEqual(
                {line.split("\t")[2] for line in trace.splitlines()[1:]},
                {"before-pcre", "pcre", "post-pcre-before-deep-parse", "deep-parse"},
            )
            self.assertTrue((root / "provenance/resources.tsv").is_file())

    def test_post_pcre_boundary_waits_for_headroom(self):
        high = {
            "rss_kb": capture.POST_PCRE_RSS_BUDGET_KB + 1,
            "pss_kb": capture.POST_PCRE_RSS_BUDGET_KB + 1,
            "vas_kb": capture.POST_PCRE_RSS_BUDGET_KB + 1,
            "swap_kb": 0,
            "minor_faults": 0,
            "major_faults": 0,
            "read_bytes": 0,
            "write_bytes": 0,
            "cancelled_write_bytes": 0,
            "root_rss_kb": capture.POST_PCRE_RSS_BUDGET_KB + 1,
            "process_count": 1,
        }
        low = dict(high)
        low.update({
            "rss_kb": capture.POST_PCRE_RSS_BUDGET_KB - 1,
            "pss_kb": capture.POST_PCRE_RSS_BUDGET_KB - 1,
            "vas_kb": capture.POST_PCRE_RSS_BUDGET_KB - 1,
            "root_rss_kb": capture.POST_PCRE_RSS_BUDGET_KB - 1,
        })
        with tempfile.TemporaryDirectory(prefix="largefile-phase-ack-") as directory:
            ack = Path(directory) / "post-pcre.ack"
            with mock.patch.object(capture, "metric_sample", side_effect=[high, low]), \
                    mock.patch.object(capture.time, "sleep"):
                measurement = capture.phase_event_measurement(
                    "post-pcre", 123, {"oom_cgroup_digest": "0" * 64}, ack
                )
            self.assertIsNotNone(measurement)
            self.assertEqual(measurement[1]["rss_kb"], capture.POST_PCRE_RSS_BUDGET_KB - 1)
            self.assertEqual(ack.read_text(encoding="ascii"), "post-pcre\n")

    def test_transitional_post_pcre_sample_counts_as_pcre(self):
        current = {
            "sample_count": 0,
            **{field: 0 for field in capture.METRIC_FIELDS},
            "temporary_peak_bytes": 0,
            "oom_events_peak": 0,
            "oom_kill_events_peak": 0,
            "oom_cgroup_count": 0,
            "oom_cgroup_digest": "",
        }
        metric = {
            "rss_kb": capture.POST_PCRE_RSS_BUDGET_KB + 1,
            "pss_kb": capture.POST_PCRE_RSS_BUDGET_KB + 1,
            "vas_kb": capture.POST_PCRE_RSS_BUDGET_KB + 1,
            "swap_kb": 0,
            "minor_faults": 0,
            "major_faults": 0,
            "read_bytes": 0,
            "write_bytes": 0,
            "cancelled_write_bytes": 0,
        }
        oom = {
            "oom_events": 0,
            "oom_kill_events": 0,
            "oom_cgroup_count": 1,
            "oom_cgroup_digest": "0" * 64,
        }
        phase_peaks = {"pcre_rss_peak_kb": None, "post_pcre_rss_peak_kb": None}
        capture.record_sample_measurement(
            metric, oom, 0, "post-pcre", oom.copy(), current, phase_peaks
        )
        self.assertEqual(phase_peaks["pcre_rss_peak_kb"], metric["rss_kb"])
        self.assertIsNone(phase_peaks["post_pcre_rss_peak_kb"])

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
                process_log=None,
                sample_log=None,
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
