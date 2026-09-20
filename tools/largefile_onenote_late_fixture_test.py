#!/usr/bin/env python3
"""Deterministic framing tests for the materialized OneNote fixture tool."""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

import largefile_onenote_late_fixture as fixture


class LateFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = (
            Path(__file__).resolve().parents[1]
            / "libclamav_rust"
            / "onenote_parser"
            / "tests"
            / "samples"
            / "New Section 1.one"
        )

    def test_prefix_has_one_byte_compact_type_and_end_marker(self) -> None:
        payload_size = fixture.FORMER_WHOLE_INPUT_CAP
        expected = (
            b"\x0c\x00\x00\x00\x15\x14\x00\x80"
            + struct.pack("<Q", payload_size)
        )
        self.assertEqual(fixture.build_prefix(payload_size), expected)
        self.assertEqual(fixture.DATA_ELEMENT_END, b"\x05")

    def test_source_package_and_first_element_are_admissible(self) -> None:
        source = self.source.read_bytes()
        package_start = fixture.find_package_start(source)
        self.assertEqual(source[package_start : package_start + 2], b"\xac\x02")
        first_element = package_start + 3
        header = struct.unpack_from("<H", source, first_element)[0]
        self.assertEqual((header >> 3) & 0x3F, fixture.DATA_ELEMENT_TYPE)

    def test_payload_below_cap_is_rejected_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "late.one"
            with self.assertRaises(ValueError):
                fixture.write_fixture(
                    self.source,
                    output,
                    fixture.FORMER_WHOLE_INPUT_CAP - 1,
                )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
