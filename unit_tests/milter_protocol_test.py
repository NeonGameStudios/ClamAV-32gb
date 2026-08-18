#!/usr/bin/env python3

"""Exercise clamav-milter through the libmilter protocol.

The default wire fixture deliberately uses a small limit so the test remains
fast and does not allocate a multi-gigabyte message.  Set MILTER_EXACT_EDGE=1
for a manual, literal 32 GiB body transfer; that mode streams fixed-size
chunks and is not part of the default CTest run.  The 4 GiB/32 GiB arithmetic
and overflow boundaries remain covered by check_clamfi_quota.  For bounded
diagnostics, MILTER_WIRE_LIMIT_BYTES can select a smaller manual limit and
MILTER_WIRE_FILL_BYTE selects the repeated body byte.
"""

import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time


DEFAULT_MAX_FILE_SIZE = 256
EXACT_EDGE_FILE_SIZE = 32 * 1024 * 1024 * 1024
MARKER = bytes.fromhex("434c414d41562d4d494c5445522d5445535400")
DATABASE_SUFFIXES = {
    ".cdb",
    ".crtdb",
    ".fp",
    ".hdb",
    ".hdu",
    ".ldb",
    ".ndb",
    ".pdb",
    ".sfp",
}

# Milter protocol negotiation flags.
SMFIP_NOCONNECT = 0x00000001
SMFIP_NOHELO = 0x00000002
SMFIP_NOMAIL = 0x00000004
SMFIP_NORCPT = 0x00000008
SMFIP_NOBODY = 0x00000010
SMFIP_NOHDRS = 0x00000020
SMFIP_NOEOH = 0x00000040
SMFIP_NR_HDR = 0x00000080
SMFIP_NR_CONN = 0x00001000
SMFIP_NR_HELO = 0x00002000
SMFIP_NR_MAIL = 0x00004000
SMFIP_NR_RCPT = 0x00008000
SMFIP_NR_EOH = 0x00040000
SMFIP_NR_BODY = 0x00080000


def packet(command, data=b""):
    if isinstance(command, str):
        command = command.encode("ascii")
    return struct.pack("!I", len(data) + 1) + command + data


def read_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise RuntimeError("milter socket closed while reading")
        result.extend(chunk)
    return bytes(result)


def receive(sock):
    length = struct.unpack("!I", read_exact(sock, 4))[0]
    if length < 1 or length > 10 * 1024 * 1024:
        raise RuntimeError("invalid milter packet length: {}".format(length))
    payload = read_exact(sock, length)
    return chr(payload[0]), payload[1:]


def send(sock, command, data=b""):
    sock.sendall(packet(command, data))


def expect(sock, expected=None):
    command, data = receive(sock)
    if expected is not None and command not in expected:
        raise RuntimeError("expected {!r}, received {!r}".format(expected, command))
    return command, data


def stage(sock, command, data, skip_flag, no_reply_flag, protocol):
    if protocol & skip_flag:
        return None
    send(sock, command, data)
    if protocol & no_reply_flag:
        return None
    return expect(sock)


def negotiate(sock):
    send(sock, "O", struct.pack("!III", 6, 0x000001FF, 0x001FFFFF))
    command, data = expect(sock, {"O"})
    if len(data) != 12:
        raise RuntimeError("invalid option negotiation payload length")
    version, actions, protocol = struct.unpack("!III", data)
    if version > 6 or actions & ~0x000001FF or protocol & ~0x001FFFFF:
        raise RuntimeError("invalid option negotiation response")
    return protocol


def begin_message(sock):
    protocol = negotiate(sock)

    stage(
        sock,
        "C",
        b"client.example.test\0" + b"4" + struct.pack("!H", 25) + b"198.51.100.7\0",
        SMFIP_NOCONNECT,
        SMFIP_NR_CONN,
        protocol,
    )
    stage(sock, "H", b"EHLO client.example.test\0", SMFIP_NOHELO, SMFIP_NR_HELO, protocol)
    stage(sock, "M", b"<sender@example.test>\0", SMFIP_NOMAIL, SMFIP_NR_MAIL, protocol)
    stage(sock, "R", b"<recipient@example.test>\0", SMFIP_NORCPT, SMFIP_NR_RCPT, protocol)
    stage(
        sock,
        "L",
        b"Subject\0protocol integration\0",
        SMFIP_NOHDRS,
        SMFIP_NR_HDR,
        protocol,
    )
    stage(sock, "N", b"", SMFIP_NOEOH, SMFIP_NR_EOH, protocol)
    return protocol


def run_case(milter_socket, body, expected_final=None, expected_body=None):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(60)
    try:
        sock.connect(str(milter_socket))
        protocol = begin_message(sock)

        body_reply = stage(sock, "B", body, SMFIP_NOBODY, SMFIP_NR_BODY, protocol)
        if body_reply is not None and body_reply[0] != "c":
            if expected_body is not None and body_reply[0] != expected_body:
                raise RuntimeError("unexpected body action: {!r}".format(body_reply[0]))
            return body_reply[0]
        if expected_body is not None:
            raise RuntimeError("body action was not returned")

        send(sock, "E")
        while True:
            command, _ = receive(sock)
            if command in "adrtf4q":
                if expected_final is not None and command != expected_final:
                    raise RuntimeError("unexpected final action: {!r}".format(command))
                send(sock, "Q")
                return command
    finally:
        sock.close()


def send_body_chunk(sock, protocol, body):
    send(sock, "B", body)
    if protocol & SMFIP_NOBODY:
        raise RuntimeError("milter negotiated away the body callback")
    if protocol & SMFIP_NR_BODY:
        return
    command, _ = expect(sock)
    if command != "c":
        raise RuntimeError("unexpected body action: {!r}".format(command))


def run_exact_edge_case(milter_socket, body_size, marker, chunk_size, fill_byte):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(300)
    try:
        sock.connect(str(milter_socket))
        protocol = begin_message(sock)
        if body_size < len(marker):
            raise RuntimeError("exact-edge body is shorter than the marker")

        filler = bytes([fill_byte]) * chunk_size
        remaining = body_size - len(marker)
        sent = 0
        next_report = 256 * 1024 * 1024
        try:
            while remaining:
                length = min(remaining, len(filler))
                send_body_chunk(sock, protocol, filler[:length])
                remaining -= length
                sent += length
                if sent >= next_report:
                    print("milter exact-edge progress: {} body bytes".format(sent), flush=True)
                    next_report += 256 * 1024 * 1024

            send_body_chunk(sock, protocol, marker)
        except BrokenPipeError as error:
            raise RuntimeError("milter socket broke after {} body bytes: {}".format(sent, error)) from error

        sent += len(marker)
        send(sock, "E")
        while True:
            command, _ = receive(sock)
            if command in "adrtf4q":
                if command != "r":
                    raise RuntimeError("unexpected exact-edge final action: {!r}".format(command))
                send(sock, "Q")
                return sent, command
    finally:
        sock.close()


def wait_for_socket(path, process, log_path):
    deadline = time.time() + 20
    while time.time() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            break
        time.sleep(0.1)
    log = log_path.read_text(errors="replace") if log_path.exists() else "<no log>"
    raise RuntimeError("process did not create {}:\n{}".format(path, log[-4000:]))


def stop_process(process, graceful_signal=None):
    if process is None or process.poll() is not None:
        return
    if graceful_signal is not None:
        process.send_signal(graceful_signal)
        try:
            process.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            pass
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def main():
    clamd = os.environ.get("CLAMD")
    milter = os.environ.get("CLAMAV_MILTER")
    certs = os.environ.get("CVD_CERTS_DIR")
    if not clamd or not milter or not certs:
        raise RuntimeError("CLAMD, CLAMAV_MILTER, and CVD_CERTS_DIR are required")

    exact_edge = os.environ.get("MILTER_EXACT_EDGE") == "1"
    wire_limit = os.environ.get("MILTER_WIRE_LIMIT_BYTES")
    if wire_limit is not None:
        max_file_size = int(wire_limit, 0)
        if max_file_size < DEFAULT_MAX_FILE_SIZE or max_file_size > EXACT_EDGE_FILE_SIZE:
            raise RuntimeError("MILTER_WIRE_LIMIT_BYTES must be between 256 and 34359738368")
    else:
        max_file_size = EXACT_EDGE_FILE_SIZE if exact_edge else DEFAULT_MAX_FILE_SIZE
    manual_wire = exact_edge or wire_limit is not None
    chunk_size = int(os.environ.get("MILTER_WIRE_CHUNK_BYTES", 32 * 1024))
    # Keep the payload below libmilter's maximum frame once the protocol
    # command byte is included.  64 KiB payloads reset the connection on the
    # tested libmilter implementation before EOM, so 32 KiB is the safe upper
    # bound for this diagnostic harness.
    if chunk_size < 1 or chunk_size > 32 * 1024:
        raise RuntimeError("MILTER_WIRE_CHUNK_BYTES must be between 1 and 32768")
    fill_byte = int(os.environ.get("MILTER_WIRE_FILL_BYTE", "90"), 0)
    if fill_byte < 0 or fill_byte > 255:
        raise RuntimeError("MILTER_WIRE_FILL_BYTE must be between 0 and 255")
    test_root = os.environ.get("MILTER_TEST_ROOT", "/tmp")
    Path(test_root).mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="clamav-milter-", dir=test_root))
    preserve_root = os.environ.get("MILTER_PRESERVE_ROOT") == "1"
    read_timeout = 600 if manual_wire else 60
    command_read_timeout = 600 if manual_wire else 30
    db = root / "db"
    tmp = root / "tmp"
    logs = root / "logs"
    db.mkdir()
    tmp.mkdir()
    logs.mkdir()
    (db / "milter-protocol.ndb").write_text("Milter.Protocol.Test:0:*:{}\n".format(MARKER.hex()))
    extra_database = os.environ.get("MILTER_EXTRA_DATABASE")
    if extra_database:
        extra_path = Path(extra_database)
        if not extra_path.is_dir():
            raise RuntimeError("MILTER_EXTRA_DATABASE is not a directory: {}".format(extra_path))
        for source in extra_path.rglob("*"):
            if source.is_file() and source.suffix.lower() in DATABASE_SUFFIXES:
                shutil.copy2(source, db / ("extra-" + source.name))

    clamd_socket = root / "clamd.sock"
    milter_socket = root / "milter.sock"
    clamd_log = logs / "clamd.log"
    milter_log = logs / "milter.log"
    clamd_config = root / "clamd.conf"
    milter_config = root / "milter.conf"
    clamd_config.write_text(
        "\n".join(
            [
                "Foreground yes",
                "PidFile {}".format(root / "clamd.pid"),
                "LocalSocket {}".format(clamd_socket),
                "LocalSocketMode 600",
                "FixStaleSocket yes",
                "DatabaseDirectory {}".format(db),
                "TemporaryDirectory {}".format(tmp),
                "LogFile {}".format(clamd_log),
                "LogFileMaxSize 1M",
                "LogTime yes",
                "LogVerbose yes",
                "ExitOnOOM yes",
                "DisableCache yes",
                "ConcurrentDatabaseReload no",
                "MaxThreads 1",
                "MaxQueue 4",
                "ReadTimeout {}".format(read_timeout),
                "CommandReadTimeout {}".format(command_read_timeout),
                "MaxScanTime 600000",
                "MaxFileSize 32G",
                "MaxScanSize 32G",
                "StreamMaxLength 32G",
                "AlertExceedsMax yes",
                "",
            ]
        )
    )
    milter_config.write_text(
        "\n".join(
            [
                "MilterSocket {}".format(milter_socket),
                "MilterSocketMode 600",
                "FixStaleSocket yes",
                "ClamdSocket unix:{}".format(clamd_socket),
                "TemporaryDirectory {}".format(tmp),
                "MaxFileSize {}".format(max_file_size),
                "ReadTimeout {}".format(read_timeout),
                "Foreground yes",
                "PidFile {}".format(root / "milter.pid"),
                "LogFile {}".format(milter_log),
                "LogFileMaxSize 1M",
                "LogFileUnlock yes",
                "LogTime yes",
                "LogVerbose yes",
                "OnFail Defer",
                "OnClean Accept",
                "OnInfected Reject",
                "AddHeader No",
                "",
            ]
        )
    )

    environment = os.environ.copy()
    clamd_process = None
    milter_process = None
    try:
        with clamd_log.open("wb") as output:
            clamd_process = subprocess.Popen(
                [clamd, "--config-file={}".format(clamd_config)],
                env=environment,
                cwd=str(root),
                stdout=output,
                stderr=subprocess.STDOUT,
            )
        wait_for_socket(clamd_socket, clamd_process, clamd_log)

        with milter_log.open("wb") as output:
            milter_process = subprocess.Popen(
                [milter, "--config-file={}".format(milter_config)],
                env=environment,
                cwd=str(root),
                stdout=output,
                stderr=subprocess.STDOUT,
            )
        wait_for_socket(milter_socket, milter_process, milter_log)

        before_body = len(b"From clamav-milter\n") + len(b"Subject: protocol integration\r\n") + 2
        if manual_wire:
            body_size = max_file_size - before_body
            sent, result = run_exact_edge_case(milter_socket, body_size, MARKER, chunk_size, fill_byte)
            if sent != body_size:
                raise RuntimeError("exact-edge body byte count mismatch: {} != {}".format(sent, body_size))
            print(
                "milter manual wire: body_bytes={} message_bytes={} limit_bytes={} result={} chunk_bytes={} fill_byte={} (extra database: {})".format(
                    sent, sent + before_body, max_file_size, result, chunk_size, fill_byte, extra_database or "none"
                )
            )
        else:
            exact_body = b"A" * (max_file_size - before_body)
            over_body = b"B" * (max_file_size - before_body + 1)
            results = {
                "clean": run_case(milter_socket, b"clean body", expected_final="a"),
                "infected": run_case(milter_socket, b"prefix:" + MARKER, expected_final="r"),
                "exact_limit": run_case(milter_socket, exact_body, expected_final="a"),
                "limit_plus_one": run_case(milter_socket, over_body, expected_body="t"),
            }
            if results != {
                "clean": "a",
                "infected": "r",
                "exact_limit": "a",
                "limit_plus_one": "t",
            }:
                raise RuntimeError("unexpected milter results: {!r}".format(results))
            print("milter protocol cases: {} (extra database: {})".format(results, extra_database or "none"))
    finally:
        stop_process(milter_process, signal.SIGUSR1)
        stop_process(clamd_process)
        if preserve_root:
            print("milter evidence root preserved: {}".format(root))
        else:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
