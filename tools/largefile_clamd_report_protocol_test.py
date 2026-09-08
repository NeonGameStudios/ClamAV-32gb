#!/usr/bin/env python3
"""Integration test for the FILDESREPORT descriptor/report wire contract."""

from __future__ import annotations

import csv
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest import mock

import largefile_clamd_report_protocol as protocol
import largefile_service_workload_check as workload_check


class FildesReportProtocolTests(unittest.TestCase):
    def setUp(self):
        requested_tmp = os.environ.get("TMPDIR") or os.environ.get("TMP")
        test_tmp = requested_tmp if requested_tmp and os.path.isdir(requested_tmp) else tempfile.gettempdir()
        self.work = tempfile.TemporaryDirectory(
            prefix="largefile-fildes-report-", dir=test_tmp
        )
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.input = self.root / "input.bin"
        self.input.write_bytes(b"xxCLAMAV-FILDES-R04yy")
        self.marker_offset = 2
        self.signature = "LargeFile.FILDESREPORT"
        self.oracle = self.root / "qualification-oracle.tsv"
        digest = hashlib.sha256(self.input.read_bytes()).hexdigest()
        placeholder = "0" * 64
        rows = [
            ["production", self.input.stat().st_size, digest, 1, "DETECTION_TERMINATED",
             self.signature, self.marker_offset, "CL_TYPE_DATA"],
            ["materialized", 1, placeholder, 0, "COMPLETE", "-", "-", "CL_TYPE_DATA"],
            ["expansion", 1, placeholder, 0, "COMPLETE", "-", "-", "CL_TYPE_DATA"],
            ["edge", 34359738368, placeholder, 0, "COMPLETE", "-", "-", "CL_TYPE_DATA"],
        ]
        with self.oracle.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
            writer.writerow(workload_check.ORACLE_HEADER)
            writer.writerows(rows)

    def test_fildesreport_passes_descriptor_and_framed_report(self):
        output = self.root / "report.json"
        client, server = socket.socketpair()
        errors = []

        def serve():
            received_fd = None
            try:
                connection = server
                command = bytearray()
                for _ in range(3):
                    data, ancillary, *_ = connection.recvmsg(
                        128, socket.CMSG_SPACE(struct.calcsize("i"))
                    )
                    if not data and not ancillary:
                        raise AssertionError("client closed before FILDESREPORT descriptor")
                    command.extend(data)
                    for level, kind, payload in ancillary:
                        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                            received_fd = struct.unpack("i", payload[:struct.calcsize("i")])[0]
                    if received_fd is not None:
                        break
                self.assertEqual(bytes(command[:15]), b"zFILDESREPORT\x00\x00")
                self.assertIsNotNone(received_fd)
                self.assertEqual(os.fstat(received_fd).st_size, self.input.stat().st_size)
                os.lseek(received_fd, 0, os.SEEK_SET)
                self.assertEqual(os.read(received_fd, 1024), self.input.read_bytes())
                report = {
                        "version": 1,
                        "status": 1,
                        "verdict": 2,
                        "completion": "DETECTION_TERMINATED",
                        "file_type": "CL_TYPE_DATA",
                        "root_size": self.input.stat().st_size,
                        "logical_bytes": self.input.stat().st_size,
                        "matcher_bytes": self.input.stat().st_size,
                        "contiguous_bytes": self.input.stat().st_size,
                        "temporary_bytes": 0,
                        "files_scanned": 1,
                        "max_recursion_depth": 0,
                        "elapsed_ms": 1,
                        "parser_operations": 1,
                        "detector_operations": 1,
                        "skipped_operations": 0,
                        "last_alert": self.signature,
                        "last_alert_offset": self.marker_offset,
                }
                payload = json.dumps(report, separators=(",", ":")).encode("utf-8")
                connection.sendall(struct.pack("!I", len(payload)) + payload + struct.pack("!I", 0))
            except Exception as error:  # pass thread failures back to the test
                errors.append(error)
            finally:
                if received_fd is not None:
                    os.close(received_fd)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            class ConnectedSocket:
                def __init__(self, wrapped):
                    self.wrapped = wrapped

                def connect(self, _path):
                    return None

                def __getattr__(self, name):
                    return getattr(self.wrapped, name)

            captured = io.StringIO()
            with mock.patch.object(
                protocol.socket, "socket", return_value=ConnectedSocket(client)
            ), contextlib.redirect_stdout(captured):
                self.assertEqual(
                    protocol.main([
                        "unused.sock", str(self.input), str(self.oracle), "production",
                        "fildes", str(output), "5",
                    ]),
                    0,
                )
        finally:
            client.close()
            server.close()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        if errors:
            raise errors[0]
        result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result["completion"], "DETECTION_TERMINATED")
        self.assertEqual(result["last_alert_offset"], self.marker_offset)
        self.assertIn(f"{self.signature} FOUND", captured.getvalue())
        self.assertIn(f"matched at {self.marker_offset}", captured.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
