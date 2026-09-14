#!/usr/bin/env python3
"""Probe clamd's 32 GiB + 1 FILDESREPORT rejection with a sparse file.

This is a metadata-boundary negative control, never materialized scan evidence.
No fixture-size override exists. The daemon must already be running on a Unix
socket with MaxFileSize=32G. Uses only the Python standard library.
"""

import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import tempfile

import largefile_acceptance_cases as acceptance_cases

MAX_FILE_SIZE = 34359738368
OVERSIZE_BYTES = 34359738369
CL_EMAXSIZE = 24  # cl_error_t in libclamav/clamav.h
LIMIT_ALERT = "Heuristics.Limits.Exceeded.MaxFileSize"
SCHEMA = "clamav-service-oversize-v1"
BUNDLE_SCHEMA = "clamav-service-oversize-both-v1"
ALERT_MODES = ("off", "on")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, label):
    require(type(value) is int and value >= 0, f"{label} must be a non-negative integer")
    return value


def validate_report(report, alert_mode=None):
    """Reject unrelated detections, limits, resource failures, and clean scans."""
    require(alert_mode in (None, *ALERT_MODES), "oversize alert mode is invalid")
    require(isinstance(report, dict), "oversize report must be an object")
    require(type(report.get("version")) is int and report["version"] == 1,
            "oversize report schema version must be 1")
    for key in ("status", "verdict", "root_size", "max_file_size", "max_scan_size",
                "temporary_bytes", "matcher_bytes", "logical_bytes", "parser_operations", "skipped_operations"):
        integer(report.get(key), f"report {key}")
    require(report["root_size"] == OVERSIZE_BYTES, "oversize report root size must be exactly 32 GiB + 1")
    require(report["max_file_size"] == MAX_FILE_SIZE, "oversize report MaxFileSize must be exactly 32 GiB")
    require(report["max_scan_size"] == 0 or report["max_scan_size"] >= OVERSIZE_BYTES,
            "oversize probe must isolate MaxFileSize from MaxScanSize")
    require(report["temporary_bytes"] == 0, "oversize descriptor rejection staged temporary content")
    require(report["matcher_bytes"] == 0, "oversize descriptor rejection performed matcher work")
    require(report["logical_bytes"] == 0, "oversize descriptor rejection charged logical bytes")
    require(report["parser_operations"] == 0, "oversize descriptor rejection performed parser work")
    require(report["skipped_operations"] > 0, "oversize rejection must record skipped work")
    require(report.get("reason") == LIMIT_ALERT, "oversize report lacks the exact MaxFileSize reason")
    if report.get("completion") == "LIMIT_INCOMPLETE":
        require(report["status"] == CL_EMAXSIZE and report["verdict"] == 0,
                "oversize incomplete report must carry CL_EMAXSIZE and a no-detection verdict")
        require(report.get("last_alert") in (None, "") and report.get("last_alert_offset") is None,
                "oversize incomplete report unexpectedly carries an alert")
    elif report.get("completion") == "DETECTION_TERMINATED":
        require(report["status"] in (0, 1) and report["verdict"] in (2, 3),
                "oversize heuristic report has contradictory status/verdict")
        require(report.get("last_alert") == LIMIT_ALERT,
                "oversize heuristic report does not name the exact MaxFileSize alert")
        # Policy alerts have no byte-offset match; unlike file signatures,
        # their optional offset is not evidence of content being inspected.
        if report.get("last_alert_offset") is not None:
            integer(report["last_alert_offset"], "oversize alert offset")
    else:
        raise ValueError("oversize report completion is not a size-limit rejection")
    if alert_mode == "off":
        require(report.get("completion") == "LIMIT_INCOMPLETE",
                "alerts-off oversize report must be incomplete")
    elif alert_mode == "on":
        require(report.get("completion") == "DETECTION_TERMINATED",
                "alerts-on oversize report must terminate on the policy alert")


def validate_evidence(evidence, alert_mode=None):
    """Recheck saved evidence after the temporary sparse fixture is removed."""
    require(isinstance(evidence, dict), "oversize evidence must be an object")
    if evidence.get("schema") == BUNDLE_SCHEMA:
        require(alert_mode is None, "an oversize bundle cannot be assigned one alert mode")
        return validate_bundle(evidence)
    require(evidence.get("schema") == SCHEMA, "unsupported oversize evidence schema")
    require(evidence.get("command") == "FILDESREPORT", "oversize evidence command must be FILDESREPORT")
    require(evidence.get("purpose") == "sparse-size-limit-rejection-only",
            "oversize evidence must not claim materialized scan qualification")
    require(evidence.get("daemon_ping_before") == "PONG" and evidence.get("daemon_ping_after") == "PONG",
            "oversize evidence lacks successful daemon health checks")
    require(evidence.get("fixture_removed") is True, "oversize fixture cleanup was not confirmed")
    actual_alert_mode = evidence.get("alert_mode")
    require(actual_alert_mode in (None, *ALERT_MODES), "oversize evidence alert mode is invalid")
    if alert_mode is not None:
        require(actual_alert_mode == alert_mode, "oversize evidence alert mode does not match its binding")
    before, after = evidence.get("fixture_before"), evidence.get("fixture_after")
    require(isinstance(before, dict) and isinstance(after, dict), "oversize fixture metadata is missing")
    for metadata in (before, after):
        for key in ("size_bytes", "allocated_bytes", "device", "inode", "mtime_ns", "ctime_ns"):
            integer(metadata.get(key), f"fixture {key}")
        require(metadata.get("regular_file") is True, "oversize fixture must be a regular file")
        require(metadata["size_bytes"] == OVERSIZE_BYTES, "oversize fixture must be exactly 32 GiB + 1")
        require(metadata["allocated_bytes"] < OVERSIZE_BYTES,
                "oversize negative control must be sparse")
    require(before == after, "oversize fixture changed during the probe")
    validate_report(evidence.get("report"), actual_alert_mode)


def validate_bundle(bundle):
    require(isinstance(bundle, dict), "oversize bundle must be an object")
    require(bundle.get("schema") == BUNDLE_SCHEMA, "unsupported oversize bundle schema")
    require(bundle.get("command") == "FILDESREPORT", "oversize bundle command must be FILDESREPORT")
    require(bundle.get("purpose") == "sparse-size-limit-rejection-both-alert-modes",
            "oversize bundle must cover both AlertExceedsMax modes")
    for mode in ALERT_MODES:
        evidence = bundle.get(f"alert_{mode}")
        require(isinstance(evidence, dict), f"oversize bundle is missing alerts-{mode} evidence")
        validate_evidence(evidence, mode)
    return bundle


def fixture_metadata(fd):
    value = os.fstat(fd)
    require(hasattr(value, "st_blocks"), "filesystem allocation evidence is unavailable")
    return {"size_bytes": value.st_size, "allocated_bytes": value.st_blocks * 512,
            "device": value.st_dev, "inode": value.st_ino,
            "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns,
            "regular_file": stat.S_ISREG(value.st_mode)}


def receive_report(connection):
    # Lazy import allows the workload verifier to import validate_evidence;
    # the existing protocol module itself imports that verifier's oracle.
    from largefile_clamd_report_protocol import receive_report as receive
    return receive(connection)


def connect(socket_path, timeout_seconds):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout_seconds)
        connection.connect(str(socket_path))
        return connection
    except BaseException:
        connection.close()
        raise


def ping(socket_path, timeout_seconds):
    with connect(socket_path, timeout_seconds) as connection:
        connection.sendall(b"zPING\x00")
        reply = bytearray()
        while len(reply) < 5:
            chunk = connection.recv(5 - len(reply))
            if not chunk:
                break
            reply.extend(chunk)
        require(reply == b"PONG\x00", "daemon did not answer PING with PONG")
    return "PONG"


def probe(socket_path, temp_dir, timeout_seconds=60, alert_mode=None):
    require(type(timeout_seconds) is int and timeout_seconds > 0, "timeout must be a positive integer")
    require(alert_mode in (None, *ALERT_MODES), "oversize alert mode is invalid")
    require(hasattr(socket, "SCM_RIGHTS"), "platform lacks Unix descriptor passing")
    evidence = {"schema": SCHEMA, "command": "FILDESREPORT",
                "purpose": "sparse-size-limit-rejection-only"}
    if alert_mode is not None:
        evidence["alert_mode"] = alert_mode
    evidence["daemon_ping_before"] = ping(socket_path, timeout_seconds)
    fd, path = tempfile.mkstemp(prefix="clamav-32g-plus-one-", dir=temp_dir)
    try:
        os.ftruncate(fd, OVERSIZE_BYTES)
        evidence["fixture_before"] = fixture_metadata(fd)
        with connect(socket_path, timeout_seconds) as connection:
            connection.sendall(b"zFILDESREPORT\x00")
            connection.sendmsg([b"\x00"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))])
            evidence["report"] = receive_report(connection)
        evidence["fixture_after"] = fixture_metadata(fd)
    finally:
        os.close(fd)
        os.unlink(path)
    evidence["fixture_removed"] = not os.path.lexists(path)
    evidence["daemon_ping_after"] = ping(socket_path, timeout_seconds)
    validate_evidence(evidence, alert_mode)
    return evidence


def combine_evidence(alert_off, alert_on):
    bundle = {"schema": BUNDLE_SCHEMA, "command": "FILDESREPORT",
              "purpose": "sparse-size-limit-rejection-both-alert-modes",
              "alert_off": alert_off, "alert_on": alert_on}
    validate_bundle(bundle)
    return bundle


def write_evidence(output, evidence):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, staging = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(evidence, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
        os.replace(staging, output)
    finally:
        if os.path.exists(staging):
            os.unlink(staging)


def main(argv):
    if argv and argv[0] == "--combine":
        if len(argv) != 4:
            print("usage: largefile_service_oversize.py --combine OUTPUT_JSON ALERT_OFF_JSON ALERT_ON_JSON", file=sys.stderr)
            return 2
        output, off_path, on_path = map(Path, argv[1:])
        bundle = combine_evidence(
            acceptance_cases.load_json_object(
                off_path.read_text(encoding="utf-8"), f"alerts-off evidence: {off_path}"
            ),
            acceptance_cases.load_json_object(
                on_path.read_text(encoding="utf-8"), f"alerts-on evidence: {on_path}"
            ),
        )
        write_evidence(output, bundle)
        return 0
    if len(argv) not in (3, 4, 5):
        print("usage: largefile_service_oversize.py SOCKET OUTPUT_JSON TEMP_DIR [TIMEOUT_SECONDS [ALERT_MODE]]", file=sys.stderr)
        return 2
    socket_path, output_path, temp_dir = argv[:3]
    timeout_seconds = int(argv[3]) if len(argv) == 4 else 60
    alert_mode = argv[4] if len(argv) == 5 else None
    if alert_mode not in (None, *ALERT_MODES):
        print("ALERT_MODE must be 'off' or 'on'", file=sys.stderr)
        return 2
    if alert_mode is None:
        evidence = probe(socket_path, temp_dir, timeout_seconds)
    else:
        evidence = probe(socket_path, temp_dir, timeout_seconds, alert_mode)
    write_evidence(output_path, evidence)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, RuntimeError) as error:
        print(f"large-file service oversize check failed: {error}", file=sys.stderr)
        sys.exit(1)
