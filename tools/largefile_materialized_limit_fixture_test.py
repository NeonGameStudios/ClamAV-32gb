#!/usr/bin/env python3
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import largefile_materialized_limit_fixture as fixture


class MaterializedLimitFixtureTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory(prefix="largefile-limit-fixture-")
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.destination = self.root / "limit.bin"

    def test_small_streamed_fixture_is_full_allocated_and_hashed(self):
        size = 1024 * 1024 + 1
        result = fixture.materialize(self.destination, size, 0, 0)
        self.assertEqual(result["size"], size)
        self.assertGreaterEqual(result["allocated_bytes"], size)
        self.assertEqual(result["first_hole"], size)
        self.assertEqual(result["tail_hex"], fixture.TAIL.hex())
        with self.destination.open("rb") as stream:
            self.assertEqual(stream.read(256), fixture.PATTERN[:256])
            stream.seek(size - len(fixture.TAIL))
            self.assertEqual(stream.read(), fixture.TAIL)
        self.assertEqual(result["sha256"], hashlib.sha256(self.destination.read_bytes()).hexdigest())
        self.assertEqual(list(self.root.iterdir()), [self.destination])

    def test_preflight_refuses_insufficient_disk_without_a_partial(self):
        with mock.patch.object(fixture.os, "statvfs", return_value=SimpleNamespace(
            f_bavail=2, f_frsize=1,
        )):
            with self.assertRaisesRegex(ValueError, "free bytes before writing"):
                fixture.materialize(self.destination, 1024, 0, 0)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_destination_is_never_replaced(self):
        self.destination.write_bytes(b"existing evidence")
        with self.assertRaisesRegex(ValueError, "new absolute file"):
            fixture.materialize(self.destination, 1024, 0, 0)
        self.assertEqual(self.destination.read_bytes(), b"existing evidence")

    def test_write_failure_removes_only_its_new_partial(self):
        real_write = os.write
        calls = 0

        def failing_write(fd, data):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected disk failure")
            return real_write(fd, data)

        with mock.patch.object(fixture.os, "write", side_effect=failing_write):
            with self.assertRaisesRegex(OSError, "injected disk failure"):
                fixture.materialize(self.destination, fixture.CHUNK_SIZE + 128, 0, 0)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_pinned_digest_accepts_independently_constructed_pattern(self):
        size = 1024 * 1024 + 1
        pattern = bytes(range(256))
        expected_bytes = (pattern * ((size - len(fixture.TAIL) + 255) // 256))[
            :size - len(fixture.TAIL)] + fixture.TAIL
        expected_sha256 = hashlib.sha256(expected_bytes).hexdigest()
        with mock.patch.object(fixture, "LIMIT_SIZE", size), \
                mock.patch.object(fixture, "LIMIT_EXPECTED_SHA256", expected_sha256):
            result = fixture.materialize(self.destination, size, 0, 0)
        self.assertEqual(result["sha256"], expected_sha256)
        self.assertEqual(self.destination.read_bytes(), expected_bytes)

    def test_pinned_digest_mismatch_never_publishes_destination(self):
        size = 1024 * 1024 + 1
        with mock.patch.object(fixture, "LIMIT_SIZE", size), \
                mock.patch.object(fixture, "LIMIT_EXPECTED_SHA256", "0" * 64):
            with self.assertRaisesRegex(ValueError, "independently pinned"):
                fixture.materialize(self.destination, size, 0, 0)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_cli_requires_explicit_full_write_acknowledgment(self):
        with self.assertRaises(SystemExit) as result:
            fixture.main([str(self.destination)])
        self.assertEqual(result.exception.code, 2)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
