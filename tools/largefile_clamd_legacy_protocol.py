#!/usr/bin/env python3
"""Exercise one legacy clamd command and validate its text reply.

The structured-report probe intentionally remains separate.  This helper
exists for the legacy SCAN/CONTSCAN/MULTISCAN/ALLMATCHSCAN/FILDES/INSTREAM
wire paths, whose replies do not contain the structured counters or exact
alert offset required by an R04 acceptance record.  It therefore produces
development/service log evidence only; the service workload verifier keeps
these cases distinct from report-backed records.
"""

from __future__ import annotations

import hashlib
import os
import re
import socket
import struct
import sys
from pathlib import Path

from largefile_service_workload_check import load_oracle, validate_outcome


MAX_REPLY_BYTES = 1024 * 1024
PATH_COMMANDS = {
    "scan": b"zSCAN ",
    "contscan": b"zCONTSCAN ",
    "multiscan": b"zMULTISCAN ",
    "allmatchscan": b"zALLMATCHSCAN ",
}


def fail(message: str) -> None:
    raise RuntimeError(message)


def read_input_digest(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def validate_input(path: Path, oracle: tuple[int, str, int, str, str, str, str]) -> None:
    expected_size, expected_digest = oracle[:2]
    actual_size, actual_digest = read_input_digest(path)
    if actual_size != expected_size:
        fail(f"input size {actual_size} does not match oracle {expected_size}")
    if actual_digest != expected_digest.lower():
        fail("input SHA-256 does not match oracle")


def _safe_path(path: str) -> bytes:
    encoded = os.fsencode(path)
    if b"\x00" in encoded or b"\n" in encoded:
        fail("qualification path cannot contain a protocol delimiter")
    return encoded


def send_path_request(sock: socket.socket, mode: str, path: str) -> None:
    command = PATH_COMMANDS.get(mode)
    if command is None:
        fail(f"unsupported legacy path mode: {mode}")
    sock.sendall(command + _safe_path(path) + b"\x00")


def send_fildes_request(sock: socket.socket, path: str) -> None:
    if not hasattr(socket, "SCM_RIGHTS"):
        fail("platform does not provide SCM_RIGHTS")
    fd = os.open(path, os.O_RDONLY)
    try:
        sock.sendall(b"zFILDES\x00")
        sock.sendmsg(
            [b"\x00"],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))],
        )
    finally:
        os.close(fd)


def send_instream_request(sock: socket.socket, path: str) -> None:
    sock.sendall(b"zINSTREAM\x00")
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            sock.sendall(struct.pack("!I", len(chunk)) + chunk)
    sock.sendall(struct.pack("!I", 0))


def receive_reply(sock: socket.socket) -> str:
    data = bytearray()
    while True:
        if len(data) >= MAX_REPLY_BYTES:
            fail(f"clamd legacy reply exceeds {MAX_REPLY_BYTES} bytes")
        chunk = sock.recv(min(65536, MAX_REPLY_BYTES - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in data or b"\x00" in data:
            break
    if not data:
        fail("clamd closed the socket before a legacy reply")
    terminators = [index for index in (data.find(b"\n"), data.find(b"\x00")) if index >= 0]
    if not terminators:
        fail("clamd closed the socket before completing a legacy reply")
    payload = bytes(data[:min(terminators)])
    try:
        # The z-prefixed protocol uses NUL termination while the old-style
        # protocol uses LF.  Normalize either wire form to one log line.
        return payload.decode("utf-8") + "\n"
    except UnicodeDecodeError as error:
        fail(f"clamd returned a non-UTF-8 legacy reply: {error}")


def validate_reply(
    reply: str,
    mode: str,
    oracle: tuple[int, str, int, str, str, str, str],
) -> None:
    expected_exit, expected_completion, expected_signature = oracle[2:5]
    validate_outcome(f"{mode} oracle", expected_exit, expected_completion, expected_signature)
    if expected_completion == "DETECTION_TERMINATED":
        escaped = re.escape(expected_signature)
        if not expected_signature.endswith(".UNOFFICIAL"):
            escaped += r"(?:\.UNOFFICIAL)?"
        if re.search(rf"^.*: {escaped}(?:\([0-9a-fA-F]+:[0-9]+\))? FOUND[ \t]*$",
                     reply, re.MULTILINE) is None:
            fail(f"{mode} legacy reply does not contain the expected detection")
        return
    if "FOUND" in reply:
        fail(f"{mode} legacy reply contains an unexpected detection")
    if expected_completion == "COMPLETE":
        if re.search(r": OK[ \t]*$", reply, re.MULTILINE) is None:
            fail(f"{mode} legacy reply does not prove a clean result")
        return
    if expected_completion == "LIMIT_INCOMPLETE":
        limit_text = reply.lower()
        if "maxfilesize" not in limit_text and "max file size" not in limit_text and \
                "size limit exceeded" not in limit_text and \
                "exceeded max scan size" not in limit_text:
            fail(f"{mode} legacy reply does not contain the size-limit diagnostic")
        if "ERROR" not in reply:
            fail(f"{mode} legacy size-limit reply is not an error result")
        return
    fail(f"{mode} oracle has unsupported legacy completion {expected_completion}")


def main(argv: list[str]) -> int:
    if len(argv) not in (5, 6):
        print(
            "usage: largefile_clamd_legacy_protocol.py SOCKET FILE ORACLE ROLE MODE [TIMEOUT_SECONDS]",
            file=sys.stderr,
        )
        return 2
    socket_path, scan_file, oracle_path, role, mode = argv[:5]
    timeout_seconds = int(argv[5]) if len(argv) == 6 else 900
    if timeout_seconds <= 0:
        fail("protocol timeout must be positive")
    path = Path(scan_file)
    oracle = load_oracle(Path(oracle_path))[role]
    validate_input(path, oracle)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout_seconds)
        sock.connect(socket_path)
        if mode in PATH_COMMANDS:
            send_path_request(sock, mode, scan_file)
        elif mode == "fildes":
            send_fildes_request(sock, scan_file)
        elif mode == "instream":
            send_instream_request(sock, scan_file)
        else:
            fail(f"unsupported legacy mode: {mode}")
        reply = receive_reply(sock)
    validate_reply(reply, mode, oracle)
    print(f"protocol_mode={mode.upper()}")
    print(f"reply={reply.rstrip()}")
    print(reply, end="" if reply.endswith("\n") else "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (KeyError, OSError, ValueError, RuntimeError) as error:
        print(f"large-file clamd legacy protocol check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
