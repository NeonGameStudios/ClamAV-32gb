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

    def test_custom_sizes_round_trip_through_streaming_fixture_and_oracle(self):
        custom = Path(self.work.name) / "late-member-custom.zip"
        prefix_size = 2 * 1024 * 1024 + 3
        target_prefix_size = 1024 * 1024 + 5
        fixture.build_fixture(
            custom,
            prefix_size=prefix_size,
            target_prefix_size=target_prefix_size,
        )
        oracle = fixture.build_oracle(custom)
        self.assertEqual(
            oracle["target_member_size"],
            target_prefix_size + len(fixture.MARKER) + 1,
        )
        self.assertGreater(oracle["marker_file_offset"], prefix_size)
        self.assertEqual(oracle["fixture_size"], custom.stat().st_size)
        self.assertEqual(fixture.validate_oracle(custom, oracle), oracle)

    def test_zip64_directory_metadata_is_parsed(self):
        original = self.path.read_bytes()
        eocd_offset = original.rfind(b"PK\x05\x06")
        eocd = fixture.EOCD.unpack(original[eocd_offset:eocd_offset + fixture.EOCD.size])
        zip64_offset = eocd_offset
        zip64 = fixture.ZIP64_EOCD.pack(
            b"PK\x06\x06",
            44,
            45,
            45,
            0,
            0,
            eocd[3],
            eocd[4],
            eocd[5],
            eocd[6],
        )
        locator = fixture.ZIP64_LOCATOR.pack(b"PK\x06\x07", 0, zip64_offset, 1)
        legacy = fixture.EOCD.pack(
            b"PK\x05\x06",
            0,
            0,
            fixture.UINT16_MAX,
            fixture.UINT16_MAX,
            fixture.UINT32_MAX,
            fixture.UINT32_MAX,
            0,
        )
        zip64_path = Path(self.work.name) / "late-member-zip64.zip"
        zip64_path.write_bytes(original[:eocd_offset] + zip64 + locator + legacy)
        oracle = fixture.build_oracle(zip64_path)
        for key in (
            "version",
            "target_member",
            "target_member_data_offset",
            "target_member_size",
            "marker",
            "marker_member_offset",
            "marker_file_offset",
            "marker_sha256",
        ):
            self.assertEqual(oracle[key], self.oracle[key], key)
        self.assertEqual(
            oracle["fixture_size"],
            self.oracle["fixture_size"] + fixture.ZIP64_EOCD.size + fixture.ZIP64_LOCATOR.size,
        )
        self.assertNotEqual(oracle["fixture_sha256"], self.oracle["fixture_sha256"])

    def test_zip64_extra_values_preserve_original_field_positions(self):
        extra = fixture.struct.pack(
            "<HHQQQ", 0x0001, 24, 111, 222, 333
        )
        self.assertEqual(
            fixture._zip64_extra_values(extra, (True, True, False)),
            [111, 222, None],
        )
        self.assertEqual(
            fixture._zip64_extra_values(
                fixture.struct.pack("<HHQ", 0x0001, 8, 333),
                (False, False, True),
            ),
            [None, None, 333],
        )

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
