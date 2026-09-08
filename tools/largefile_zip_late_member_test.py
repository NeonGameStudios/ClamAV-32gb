#!/usr/bin/env python3
import json
from pathlib import Path
import tempfile
import unittest

import largefile_zip_late_member as fixture


class ZipLateMemberTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="largefile-zip-late-")
        self.addCleanup(self.work.cleanup)
        self.path = Path(self.work.name) / "late-member.zip"
        fixture.build_fixture(self.path)
        self.oracle = fixture.build_oracle(self.path)

    def test_oracle_binds_late_member_and_marker_offset(self):
        self.assertEqual(self.oracle["version"], 1)
        self.assertEqual(self.oracle["target_member"], fixture.TARGET_MEMBER)
        self.assertGreater(self.oracle["marker_file_offset"], fixture.PREFIX_SIZE)
        self.assertEqual(
            fixture.validate_oracle(self.path, json.loads(json.dumps(self.oracle))),
            self.oracle,
        )

    def test_fixture_bytes_are_reproducible(self):
        second = Path(self.work.name) / "late-member-second.zip"
        fixture.build_fixture(second)
        self.assertEqual(self.path.read_bytes(), second.read_bytes())

    def test_marker_tampering_is_rejected_by_raw_oracle(self):
        data = bytearray(self.path.read_bytes())
        marker_offset = self.oracle["marker_file_offset"]
        data[marker_offset] ^= 0x01
        self.path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "CRC|exactly one marker"):
            fixture.build_oracle(self.path)

    def test_truncated_member_is_rejected(self):
        self.path.write_bytes(self.path.read_bytes()[:-1])
        with self.assertRaisesRegex(ValueError, "end-of-central-directory|comment length"):
            fixture.build_oracle(self.path)

    def test_empty_archive_is_rejected_without_index_error(self):
        empty = Path(self.work.name) / "empty.zip"
        with fixture.zipfile.ZipFile(empty, "w", allowZip64=False):
            pass
        with self.assertRaisesRegex(ValueError, "no entries"):
            fixture.build_oracle(empty)


if __name__ == "__main__":
    unittest.main(verbosity=2)
