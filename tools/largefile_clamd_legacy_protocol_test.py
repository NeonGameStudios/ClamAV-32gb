#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import socket
import struct
import tempfile
import unittest

import largefile_clamd_legacy_protocol as protocol


class LegacyClamdProtocolTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="largefile-clamd-legacy-")
        self.addCleanup(self.work.cleanup)
        self.input = Path(self.work.name) / "input.bin"
        self.input.write_bytes(b"legacy fixture")
        digest = protocol.read_input_digest(self.input)[1]
        self.clean = (
            self.input.stat().st_size, digest, 0, "COMPLETE", "-", "-", "CL_TYPE_DATA"
        )
        self.detection = (
            self.input.stat().st_size, digest, 1, "DETECTION_TERMINATED",
            "Legacy.Detection", "7", "CL_TYPE_DATA"
        )
        self.limit = (
            self.input.stat().st_size, digest, 2, "LIMIT_INCOMPLETE", "-", "-", "CL_TYPE_DATA"
        )

    def test_path_request_has_exact_legacy_wire(self):
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        protocol.send_path_request(client, "contscan", "/tmp/fixture")
        self.assertEqual(server.recv(128), b"zCONTSCAN /tmp/fixture\x00")

    def test_fildes_request_passes_descriptor(self):
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        protocol.send_fildes_request(client, str(self.input))
        data, ancillary, *_ = server.recvmsg(128, socket.CMSG_SPACE(struct.calcsize("i")))
        if data == b"zFILDES\x00":
            second, second_ancillary, *_ = server.recvmsg(
                128, socket.CMSG_SPACE(struct.calcsize("i"))
            )
            data += second
            ancillary += second_ancillary
        self.assertEqual(data, b"zFILDES\x00\x00")
        received = None
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                received = struct.unpack("i", payload[:struct.calcsize("i")])[0]
        self.assertIsNotNone(received)
        try:
            self.assertEqual(os.fstat(received).st_size, self.input.stat().st_size)
        finally:
            os.close(received)

    def test_instream_request_has_terminating_zero_chunk(self):
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        protocol.send_instream_request(client, str(self.input))
        expected = (
            b"zINSTREAM\x00"
            + struct.pack("!I", self.input.stat().st_size)
            + self.input.read_bytes()
            + struct.pack("!I", 0)
        )
        self.assertEqual(server.recv(128), expected)

    def test_reply_validation_is_outcome_specific(self):
        protocol.validate_reply("fixture: OK\n", "scan", self.clean)
        protocol.validate_reply(
            "fixture: Legacy.Detection.UNOFFICIAL FOUND\n", "scan", self.detection
        )
        protocol.validate_reply(
            "stream: Exceeded max scan size ERROR\n", "instream", self.limit
        )
        with self.assertRaises(RuntimeError):
            protocol.validate_reply("fixture: OK\n", "scan", self.limit)

    def test_receive_reply_stops_after_complete_line(self):
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        server.sendall(b"fixture: OK\n")
        self.assertEqual(protocol.receive_reply(client), "fixture: OK\n")

    def test_receive_reply_normalizes_z_protocol_nul(self):
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        server.sendall(b"fixture: OK\x00")
        self.assertEqual(protocol.receive_reply(client), "fixture: OK\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
