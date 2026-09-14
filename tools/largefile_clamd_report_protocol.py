#!/usr/bin/env python3
"""Exercise one length-prefixed clamd structured-report command.

The service qualification shell harness also validates the same oracle for
the clamdscan client paths. This small probe covers the direct wire paths so
a green service gate cannot accidentally omit a structured command family. It
deliberately uses only Python's standard library.
"""

import hashlib
import json
import os
import socket
import struct
import sys
from pathlib import Path

import largefile_acceptance_cases as acceptance_cases
from largefile_service_workload_check import load_oracle as load_qualification_oracle, validate_outcome


MAX_FRAME = 16 * 1024 * 1024
REPORT_FIELDS = (
    "status",
    "verdict",
    "root_size",
    "logical_bytes",
    "matcher_bytes",
    "contiguous_bytes",
    "temporary_bytes",
    "files_scanned",
    "max_recursion_depth",
    "elapsed_ms",
    "parser_operations",
    "detector_operations",
    "skipped_operations",
)


def fail(message):
    raise RuntimeError(message)


def read_exact(sock, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            fail("clamd closed the socket before the report frame completed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_report(sock):
    frame_length = struct.unpack("!I", read_exact(sock, 4))[0]
    if frame_length == 0:
        fail("clamd returned an empty report before the JSON frame")
    if frame_length > MAX_FRAME:
        fail(f"clamd report frame exceeds {MAX_FRAME} bytes")
    try:
        report = acceptance_cases.load_json_object(
            read_exact(sock, frame_length).decode("utf-8"), "clamd report"
        )
    except (UnicodeDecodeError, ValueError) as error:
        fail(f"clamd returned invalid report JSON: {error}")
    terminator = struct.unpack("!I", read_exact(sock, 4))[0]
    if terminator != 0:
        fail("clamd report did not end with a zero-length frame")
    return report


def load_oracle(path, role):
    oracle = load_qualification_oracle(Path(path))
    if role not in oracle:
        fail(f"qualification oracle must contain one {role} row")
    size, digest, expected_exit, completion, signature, offset, file_type = oracle[role]
    return [
        role,
        str(size),
        digest,
        str(expected_exit),
        completion,
        signature,
        offset,
        file_type,
    ]


def validate_input(path, oracle):
    expected_size = int(oracle[1])
    expected_hash = oracle[2].lower()
    actual_size = os.stat(path).st_size
    if actual_size != expected_size:
        fail(f"input size {actual_size} does not match oracle {expected_size}")
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    if digest.hexdigest() != expected_hash:
        fail("input SHA-256 does not match qualification oracle")


def validate_report(report, oracle, mode, expected_size):
    expected_exit = int(oracle[3])
    expected_completion = oracle[4]
    expected_signature = oracle[5]
    expected_offset = oracle[6]
    expected_type = oracle[7]
    validate_outcome(f"{mode} oracle", expected_exit, expected_completion, expected_signature)
    if expected_exit not in (0, 1, 2):
        fail(f"{mode} oracle has an unsupported expected exit status")
    if report.get("version") != 1:
        fail(f"{mode} report schema version is not 1")
    if report.get("completion") != expected_completion:
        fail(f"{mode} completion does not match oracle")
    if report.get("file_type") != expected_type:
        fail(f"{mode} file type does not match oracle")
    for field in REPORT_FIELDS:
        value = report.get(field)
        if type(value) is not int or value < 0:
            fail(f"{mode} report field {field} is not a non-negative integer")
    if report["root_size"] != expected_size:
        fail(f"{mode} report root size does not match oracle")
    last_alert = report.get("last_alert")
    if expected_signature == "-":
        if last_alert not in (None, ""):
            fail(f"{mode} clean oracle has an unexpected alert")
        if report.get("last_alert_offset") is not None:
            fail(f"{mode} clean oracle has an unexpected alert offset")
        if report.get("verdict") not in (0, 1):
            fail(f"{mode} clean oracle has an unexpected verdict")
    elif last_alert not in (expected_signature, f"{expected_signature}.UNOFFICIAL"):
        fail(f"{mode} report alert does not exactly match the oracle")
    elif report.get("verdict") not in (2, 3):
        fail(f"{mode} detection report does not carry a non-clean verdict")
    elif type(report.get("last_alert_offset")) is not int or report["last_alert_offset"] < 0:
        fail(f"{mode} detection report does not carry a native-width alert offset")
    elif report["last_alert_offset"] != int(expected_offset):
        fail(f"{mode} report alert offset does not exactly match the oracle")
    if expected_completion == "DETECTION_TERMINATED" and report["status"] not in (0, 1):
        fail(f"{mode} report status is invalid for a detection")
    if expected_completion == "COMPLETE" and report["status"] != 0:
        fail(f"{mode} report status is non-success for expected clean result")
    if expected_exit == 2 and report["status"] == 0:
        fail(f"{mode} report status is clean for expected error exit 2")
    if expected_completion == "COMPLETE":
        if report["status"] != 0 or report.get("verdict") not in (0, 1):
            fail(f"{mode} complete report is not clean and successful")
        if report["skipped_operations"] != 0:
            fail(f"{mode} complete report contains skipped operations")
    elif expected_exit == 0:
        fail(f"{mode} non-complete oracle unexpectedly has exit 0")


def send_path_request(sock, mode, path):
    commands = {
        "scan": b"zSCANREPORT ",
        "contscan": b"zCONTSCANREPORT ",
        "multiscan": b"zMULTISCANREPORT ",
        "allmatchscan": b"zALLMATCHSCANREPORT ",
    }
    if mode not in commands:
        fail(f"unsupported path-report mode: {mode}")
    encoded_path = os.fsencode(path)
    if b"\x00" in encoded_path or b"\n" in encoded_path:
        fail("qualification path cannot contain a protocol delimiter")
    sock.sendall(commands[mode] + encoded_path + b"\x00")


def send_fildes_request(sock, path):
    if not hasattr(socket, "SCM_RIGHTS"):
        fail("platform does not provide SCM_RIGHTS")
    fd = os.open(path, os.O_RDONLY)
    try:
        sock.sendall(b"zFILDESREPORT\x00")
        sock.sendmsg(
            [b"\x00"],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))],
        )
    finally:
        os.close(fd)


def send_instream_request(sock, path):
    sock.sendall(b"zINSTREAMREPORT\x00")
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            sock.sendall(struct.pack("!I", len(chunk)) + chunk)
    sock.sendall(struct.pack("!I", 0))


def main(argv):
    if len(argv) not in (6, 7):
        print(
            "usage: largefile_clamd_report_protocol.py SOCKET FILE ORACLE ROLE MODE OUTPUT_JSON [TIMEOUT_SECONDS]",
            file=sys.stderr,
        )
        return 2
    socket_path, scan_file, oracle_path, role, mode, output_path = argv[:6]
    timeout_seconds = int(argv[6]) if len(argv) == 7 else 900
    if timeout_seconds <= 0:
        fail("protocol timeout must be positive")
    oracle = load_oracle(oracle_path, role)
    validate_input(scan_file, oracle)
    expected_size = int(oracle[1])
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout_seconds)
        sock.connect(socket_path)
        if mode in {"scan", "contscan", "multiscan", "allmatchscan"}:
            send_path_request(sock, mode, scan_file)
        elif mode == "fildes":
            send_fildes_request(sock, scan_file)
        elif mode == "instream":
            send_instream_request(sock, scan_file)
        else:
            fail(f"unsupported report mode: {mode}")
        report = receive_report(sock)
    finally:
        sock.close()
    validate_report(report, oracle, mode, expected_size)
    target = report.get("target") or scan_file
    completion = report.get("completion")
    if completion == "DETECTION_TERMINATED":
        alert = report.get("last_alert")
        print(f"{target}: {alert} FOUND")
        if isinstance(report.get("last_alert_offset"), int):
            print(f"signature {alert} matched at {report['last_alert_offset']}")
    elif completion == "COMPLETE":
        print(f"{target}: OK")
    else:
        print(f"{target}: INCOMPLETE ({report.get('reason', 'unknown')})")
    with open(output_path, "w", encoding="utf-8") as stream:
        json.dump(report, stream, separators=(",", ":"), sort_keys=True)
        stream.write("\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, RuntimeError) as error:
        print(f"large-file clamd report protocol check failed: {error}", file=sys.stderr)
        sys.exit(1)
