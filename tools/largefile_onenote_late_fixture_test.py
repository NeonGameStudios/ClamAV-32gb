#!/usr/bin/env python3
"""Deterministic framing tests for the materialized OneNote fixture tool."""

from __future__ import annotations

import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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

    def source_with_embedded_executable(self, directory: Path) -> Path:
        root = Path(__file__).resolve().parents[1]
        xor_source = (
            root
            / "unit_tests"
            / "input"
            / "clamav_hdb_scanfiles"
            / "clam.exe.webapp-export.one.xor"
        )
        xor_script = root / "unit_tests" / "input" / "xor_testfile.py"
        source = directory / "source.one"
        subprocess.run(
            [
                "python3", "-B", str(xor_script), "--in_file", str(xor_source),
                "--out_file", str(source),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return source

    def test_prefix_has_one_byte_compact_type_and_end_marker(self) -> None:
        payload_size = fixture.FORMER_WHOLE_INPUT_CAP
        expected = (
            b"\x0c\x00\x00\x00\x15\x14\x00\x80"
            + struct.pack("<Q", payload_size)
        )
        self.assertEqual(fixture.build_prefix(payload_size), expected)
        self.assertEqual(fixture.DATA_ELEMENT_END, b"\x05")

    def test_target_size_computes_exact_32gib_materialized_payload(self) -> None:
        target_bytes = 32 * 1024 * 1024 * 1024
        payload_bytes = fixture.payload_size_for_target(self.source, target_bytes)
        final_size = (
            self.source.stat().st_size
            + len(fixture.build_prefix(payload_bytes))
            + payload_bytes
            + len(fixture.DATA_ELEMENT_END)
        )

        self.assertGreaterEqual(payload_bytes, fixture.FORMER_WHOLE_INPUT_CAP)
        self.assertEqual(final_size, target_bytes)

    def test_target_size_below_large_fixture_contract_is_rejected(self) -> None:
        minimum = (
            self.source.stat().st_size
            + len(fixture.build_prefix(0))
            + fixture.FORMER_WHOLE_INPUT_CAP
            + len(fixture.DATA_ELEMENT_END)
        )
        with self.assertRaisesRegex(ValueError, "required payload beyond"):
            fixture.payload_size_for_target(self.source, minimum - 1)

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

    def test_write_all_retries_short_writes_and_rejects_no_progress(self) -> None:
        class ShortWriter:
            def __init__(self) -> None:
                self.data = bytearray()

            def write(self, data) -> int:
                count = min(3, len(data))
                self.data.extend(data[:count])
                return count

        writer = ShortWriter()
        fixture.write_all(writer, b"materialized bytes")
        self.assertEqual(writer.data, b"materialized bytes")

        class StoppedWriter:
            def write(self, data) -> int:
                return 0

        with self.assertRaisesRegex(OSError, "stopped accepting bytes"):
            fixture.write_all(StoppedWriter(), b"one byte")

    def test_materialized_corpus_places_marker_beyond_cap(self) -> None:
        root = Path(__file__).resolve().parents[1]
        xor_source = (
            root
            / "unit_tests"
            / "input"
            / "clamav_hdb_scanfiles"
            / "clam.exe.webapp-export.one.xor"
        )
        xor_script = root / "unit_tests" / "input" / "xor_testfile.py"
        generator = root / "tools" / "largefile_onenote_late_fixture.py"
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / "source.one"
            output = directory / "late.one"
            subprocess.run(
                [
                    "python3",
                    "-B",
                    str(xor_script),
                    "--in_file",
                    str(xor_source),
                    "--out_file",
                    str(source),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            source_bytes = source.read_bytes()
            payload_size = fixture.FORMER_WHOLE_INPUT_CAP
            prefix = fixture.build_prefix(payload_size)
            target_bytes = (
                len(source_bytes)
                + len(prefix)
                + payload_size
                + len(fixture.DATA_ELEMENT_END)
            )
            expected_marker = (
                source_bytes.find(b"MZ")
                + len(prefix)
                + payload_size
                + len(fixture.DATA_ELEMENT_END)
            )
            result = subprocess.run(
                [
                    "python3", "-B", str(generator), str(source), str(output),
                    "--target-bytes", str(target_bytes),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertGreater(expected_marker, fixture.FORMER_WHOLE_INPUT_CAP)
            self.assertEqual(output.stat().st_size, target_bytes)
            self.assertGreaterEqual(output.stat().st_blocks * 512, output.stat().st_size)
            self.assertIn(f"embedded_mz_offset={expected_marker}", result.stdout)
            self.assertIn(f"payload_bytes={payload_size}", result.stdout)

    def test_failed_write_removes_only_its_own_partial_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = self.source_with_embedded_executable(directory)
            output = directory / "late.one"
            write_all = fixture.write_all
            calls = 0

            def fail_on_prefix(stream, data: bytes) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated disk-full write")
                write_all(stream, data)

            with patch.object(fixture, "write_all", side_effect=fail_on_prefix):
                with self.assertRaisesRegex(OSError, "simulated disk-full"):
                    fixture.write_fixture(
                        source,
                        output,
                        fixture.FORMER_WHOLE_INPUT_CAP,
                    )

            self.assertFalse(output.exists())

    def test_failed_write_preserves_replacement_at_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = self.source_with_embedded_executable(directory)
            output = directory / "late.one"
            moved_partial = directory / "moved-partial.one"
            write_all = fixture.write_all
            calls = 0

            def replace_then_fail(stream, data: bytes) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    output.rename(moved_partial)
                    output.write_bytes(b"unrelated replacement")
                    raise OSError("simulated disk-full write")
                write_all(stream, data)

            with patch.object(fixture, "write_all", side_effect=replace_then_fail):
                with self.assertRaisesRegex(OSError, "simulated disk-full"):
                    fixture.write_fixture(
                        source,
                        output,
                        fixture.FORMER_WHOLE_INPUT_CAP,
                    )

            self.assertEqual(output.read_bytes(), b"unrelated replacement")

    def test_failed_cleanup_reports_the_partial_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = self.source_with_embedded_executable(directory)
            output = directory / "late.one"
            write_all = fixture.write_all
            calls = 0

            def fail_on_prefix(stream, data: bytes) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated disk-full write")
                write_all(stream, data)

            with patch.object(fixture, "write_all", side_effect=fail_on_prefix):
                with patch.object(Path, "unlink", side_effect=PermissionError("denied")):
                    with self.assertRaisesRegex(OSError, "partial output may remain"):
                        fixture.write_fixture(
                            source,
                            output,
                            fixture.FORMER_WHOLE_INPUT_CAP,
                        )

            self.assertTrue(output.is_file())
            output.unlink()


if __name__ == "__main__":
    unittest.main()
