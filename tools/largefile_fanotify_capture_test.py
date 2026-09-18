#!/usr/bin/env python3
"""Unit tests for the non-fabricating fanotify capture primitive."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
import largefile_fanotify_capture as capture


class FanotifyCaptureTests(unittest.TestCase):
    def test_parse_one_permission_event_retains_raw_metadata(self):
        payload = capture.EVENT_HEADER.pack(
            capture.EVENT_HEADER.size, 3, 0, capture.EVENT_HEADER.size,
            capture.FAN_OPEN_PERM, 17, 99,
        )
        rows = capture.parse_event_batch(payload)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["metadata_version"], 3)
        self.assertEqual(rows[0]["mask"], capture.FAN_OPEN_PERM)
        self.assertEqual(rows[0]["fd"], 17)
        self.assertEqual(rows[0]["raw_metadata_hex"], payload.hex())

    def test_parse_rejects_truncated_event(self):
        with self.assertRaisesRegex(capture.CaptureError, "truncated"):
            capture.parse_event_batch(b"\x00" * (capture.EVENT_HEADER.size - 1))

    def test_parse_rejects_event_length_outside_read(self):
        payload = capture.EVENT_HEADER.pack(
            capture.EVENT_HEADER.size + 1, 3, 0, capture.EVENT_HEADER.size,
            capture.FAN_OPEN_PERM, 17, 99,
        )
        with self.assertRaisesRegex(capture.CaptureError, "truncated event"):
            capture.parse_event_batch(payload)

    def test_mountinfo_decodes_private_mount(self):
        text = (
            "42 1 0:42 / /var/tmp/clamav\\040private rw,relatime - "
            "tmpfs tmpfs rw\n"
        )
        info = capture.parse_mountinfo(
            text, Path("/var/tmp/clamav private")
        )
        self.assertEqual(info.filesystem, "tmpfs")
        self.assertTrue(info.private)

    def test_mountinfo_marks_shared_mount_non_private(self):
        text = (
            "42 1 0:42 / /var/tmp/clamav rw,relatime shared:7 - "
            "ext4 /dev/vdb rw\n"
        )
        info = capture.parse_mountinfo(text, Path("/var/tmp/clamav"))
        self.assertFalse(info.private)

    def test_mask_names_require_permission_bit(self):
        self.assertEqual(capture.mask_names(capture.FAN_OPEN_PERM), ["FAN_OPEN_PERM"])
        self.assertEqual(capture.mask_names(0x40), ["0x40"])

    def test_permission_response_targets_event_fd_on_fanotify_channel(self):
        read_fd, write_fd = os.pipe()
        try:
            capture._write_response(write_fd, 23)
            self.assertEqual(capture.RESPONSE.unpack(os.read(read_fd, capture.RESPONSE.size)), (23, capture.FAN_ALLOW))
        finally:
            os.close(read_fd)
            os.close(write_fd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
