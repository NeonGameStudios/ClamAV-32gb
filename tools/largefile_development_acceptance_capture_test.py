#!/usr/bin/env python3
import json
from pathlib import Path
import stat
import tempfile
import unittest

import largefile_acceptance_cases as acceptance_cases
import largefile_development_acceptance_capture as capture


class DevelopmentAcceptanceCaptureTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="largefile-r04-capture-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.build = self.root / "build"
        self.build.mkdir()
        (self.build / "CMakeCache.txt").write_text("CMAKE_BUILD_TYPE:STRING=Debug\n", encoding="utf-8")
        self.scanner = self.root / "fake-clamscan"
        self.scanner.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "report = next(value.split('=', 1)[1] for value in sys.argv if value.startswith('--report-json='))\n"
            "database = next(value.split('=', 1)[1] for value in sys.argv if value.startswith('--database='))\n"
            "limited = '--max-filesize=8' in sys.argv\n"
            "source = sys.argv[-1]\n"
            "data = sys.stdin.buffer.read() if source == '-' else open(source, 'rb').read()\n"
            "marker = b'CLAMAV-R04-RUNTIME-DETECTION'\n"
            "base = {'version': 1, 'root_size': len(data), 'max_scan_size': 34359738368,\n"
            "'max_recursion_depth': 0, 'elapsed_ms': 1, 'logical_bytes': 0, 'matcher_bytes': 0,\n"
            "'contiguous_bytes': 0, 'temporary_bytes': 0, 'files_scanned': 0,\n"
            "'parser_operations': 0, 'detector_operations': 0, 'skipped_operations': 0,\n"
            "'last_alert': None, 'last_alert_offset': None}\n"
            "if limited:\n"
            "    result = {**base, 'status': 24, 'verdict': 0, 'completion': 'LIMIT_INCOMPLETE',\n"
            "    'logical_bytes': 0, 'matcher_bytes': 0, 'contiguous_bytes': 0, 'temporary_bytes': 0,\n"
            "    'files_scanned': 0, 'parser_operations': 0, 'detector_operations': 0,\n"
            "    'skipped_operations': 1, 'reason': 'Heuristics.Limits.Exceeded.MaxFileSize'}\n"
            "    print(f'{source}: MaxFileSize exceeded ERROR')\n"
            "    status = 2\n"
            "elif 'clean-db' in database:\n"
            "    result = {**base, 'status': 0, 'verdict': 0, 'completion': 'COMPLETE',\n"
            "    'logical_bytes': len(data), 'matcher_bytes': len(data), 'contiguous_bytes': len(data),\n"
            "    'temporary_bytes': 0, 'files_scanned': 1, 'parser_operations': 1,\n"
            "    'detector_operations': 1, 'skipped_operations': 0, 'reason': 'complete'}\n"
            "    print(f'{source}: OK')\n"
            "    status = 0\n"
            "else:\n"
            "    offset = data.index(marker)\n"
            "    result = {**base, 'status': 1, 'verdict': 2, 'completion': 'DETECTION_TERMINATED',\n"
            "    'logical_bytes': len(data), 'matcher_bytes': len(data), 'contiguous_bytes': len(data),\n"
            "    'temporary_bytes': 0, 'files_scanned': 1, 'parser_operations': 1,\n"
            "    'detector_operations': 1, 'skipped_operations': 0,\n"
            "    'last_alert': 'LargeFile.R04.Runtime.Detection.UNOFFICIAL',\n"
            "    'last_alert_offset': offset, 'reason': 'LargeFile.R04.Runtime.Detection'}\n"
            "    print(f'{source}: LargeFile.R04.Runtime.Detection.UNOFFICIAL FOUND')\n"
            "    print(f'signature LargeFile.R04.Runtime.Detection.UNOFFICIAL matched at {offset}')\n"
            "    status = 1\n"
            "with open(report, 'w', encoding='utf-8') as stream: json.dump(result, stream); stream.write('\\n')\n"
            "raise SystemExit(status)\n",
            encoding="utf-8",
        )
        self.scanner.chmod(self.scanner.stat().st_mode | stat.S_IXUSR)

    def test_capture_writes_real_bound_records_and_retained_artifacts(self):
        count = capture.capture(
            self.scanner,
            self.root / "evidence",
            Path(__file__).resolve().parents[1],
            self.build,
        )
        self.assertEqual(count, 6)
        evidence = self.root / "evidence"
        records = evidence / "provenance/acceptance-cases.tsv"
        mapping = acceptance_cases.validate_map(
            Path(__file__).resolve().parents[1] / "docs/largefile-capabilities.tsv",
            Path(__file__).resolve().parents[1] / "docs/largefile-capability-case-map.tsv",
        )
        self.assertEqual(acceptance_cases.validate_records(records, mapping, evidence_root=evidence), 6)
        rows = records.read_text(encoding="utf-8").splitlines()
        self.assertIn("clamscan:file:detection-edge", "\n".join(rows))
        self.assertIn("clamscan:stdin:detection-edge", "\n".join(rows))
        self.assertIn("clamscan:file:clean-edge", "\n".join(rows))
        self.assertIn("clamscan:stdin:limit-edge", "\n".join(rows))
        self.assertEqual(
            json.loads((evidence / "poc/reports/r04-runtime-detection.bin.jsonl").read_text())[
                "completion"
            ],
            "DETECTION_TERMINATED",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
