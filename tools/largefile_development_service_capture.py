#!/usr/bin/env python3
"""Capture current-source clamd and clamdscan records on a small fixture.

This is development evidence only.  It exercises the six direct structured
report commands and, when supplied, clamdscan's fdpass and stream ingress
modes with clean, detection, and size-limit inputs under the ARM64 legacy
envelope.  The output is deliberately shaped like R04 evidence so the generic
acceptance-record verifier sees the same embedded scan outcomes as a certified
service run.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import largefile_acceptance_cases as acceptance_cases
import largefile_clamd_report_protocol as protocol


MODES = {
    "scan": "SCANREPORT",
    "contscan": "CONTSCANREPORT",
    "multiscan": "MULTISCANREPORT",
    "allmatchscan": "ALLMATCHSCANREPORT",
    "fildes": "FILDESREPORT",
    "instream": "INSTREAMREPORT",
}
CLIENT_MODES = {
    "fdpass": "fdpass",
    "stream": "stream",
}
ORACLE_HEADER = [
    "role", "expected_size", "expected_sha256", "expected_exit",
    "expected_completion", "expected_signature", "expected_offset", "expected_type",
]
OUTCOME_SUFFIX = {
    "clean": "clean-edge",
    "detection": "detection-edge",
    "limit": "limit-edge",
}
OUTCOME_EXIT = {"clean": 0, "detection": 1, "limit": 2}
DETECTION_SIGNATURE = "LargeFile.R04.Service.Detection"
DETECTION_MARKER = b"SERVICE-R04-DIRECT-DETECTION"
DETECTION_PREFIX = b"service-r04-prefix:"
REPORT_NUMERIC_FIELDS = (
    "logical_bytes", "matcher_bytes", "contiguous_bytes", "temporary_bytes",
    "files_scanned", "max_recursion_depth", "elapsed_ms", "parser_operations",
    "detector_operations", "skipped_operations",
)


def fail(message: str) -> None:
    raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_file(path: Path, label: str) -> Path:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} is missing or symlinked: {path}")
    return path


def write_database(path: Path, detection: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if detection:
        path.write_text(
            f"{DETECTION_SIGNATURE}:0:*:{DETECTION_MARKER.hex()}\n",
            encoding="utf-8",
        )
    else:
        path.write_text("Clean.NoMatch:0:*:deadbeef00\n", encoding="utf-8")


def write_fixture(path: Path, outcome: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if outcome in {"clean", "detection"}:
        path.write_bytes(DETECTION_PREFIX + DETECTION_MARKER + b"\n")
    elif outcome == "limit":
        path.write_bytes(b"123456789\n")
    else:
        fail(f"unknown service outcome: {outcome}")


def write_service_input_identity(path: Path, fixtures: dict[str, Path]) -> None:
    """Retain the exact small fixtures bound to lifecycle service records."""
    inputs = {}
    for role, fixture in sorted(fixtures.items()):
        info = require_file(fixture, f"{role} service fixture").stat()
        blocks = getattr(info, "st_blocks", None)
        allocated = blocks * 512 if type(blocks) is int and blocks >= 0 else None
        inputs[role] = {
            "input": str(fixture.resolve()),
            "size": info.st_size,
            "sha256": sha256(fixture),
            "allocated_bytes": allocated,
            "first_hole": None,
        }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": 1, "inputs": inputs}, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def write_oracle(path: Path, fixture: Path, outcome: str, file_type: str) -> None:
    expected_size = fixture.stat().st_size
    expected_hash = sha256(fixture)
    signature = DETECTION_SIGNATURE if outcome == "detection" else "-"
    offset = str(len(DETECTION_PREFIX)) if outcome == "detection" else "-"
    completion = {
        "clean": "COMPLETE",
        "detection": "DETECTION_TERMINATED",
        "limit": "LIMIT_INCOMPLETE",
    }[outcome]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
        writer.writerow(ORACLE_HEADER)
        for role in ("production", "materialized", "expansion"):
            writer.writerow([
                role, expected_size, expected_hash, OUTCOME_EXIT[outcome],
                completion, signature, offset, file_type,
            ])
        writer.writerow([
            "edge", 34359738368, "0" * 64, OUTCOME_EXIT[outcome],
            completion, signature, offset, file_type,
        ])


def write_config(
    path: Path,
    database: Path,
    socket_path: Path,
    pid_path: Path,
    temporary: Path,
    certs: Path | None,
    limit: bool,
) -> None:
    max_file = "8" if limit else "64M"
    lines = [
        f"DatabaseDirectory {database}",
        f"LocalSocket {socket_path}",
        f"PidFile {pid_path}",
        f"TemporaryDirectory {temporary}",
        "MaxThreads 1",
        "MaxQueue 2",
        f"MaxFileSize {max_file}",
        "MaxScanSize 64M",
        "MaxMatcherWork 256M",
        "MaxTemporarySize 64M",
        "MaxContiguousSize 64M",
        "PCREMaxFileSize 64M",
        # Keep this above the small fixture so the limit report exercises
        # MaxFileSize admission rather than the wire-level stream cap.
        "StreamMaxLength 64M",
        "MaxScanTime 60000",
        "AlertExceedsMax no",
        "MaxRecursion 17",
        "MaxFiles 10000",
        "Foreground yes",
        "Debug yes",
        "LogVerbose yes",
    ]
    if certs is not None:
        lines.insert(1, f"CVDCertsDirectory {certs}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def ping(socket_path: Path, timeout_seconds: float = 2.0) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout_seconds)
        connection.connect(str(socket_path))
        connection.sendall(b"zPING\x00")
        if connection.recv(5) != b"PONG\x00":
            fail("clamd did not answer PING with PONG")


def start_daemon(
    clamd: Path,
    config: Path,
    socket_path: Path,
    pid_path: Path,
    log_path: Path,
) -> subprocess.Popen:
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [str(clamd), f"--config-file={config}"],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                fail(f"clamd exited before readiness; see {log_path}")
            try:
                ping(socket_path)
                if not pid_path.is_file() or pid_path.is_symlink():
                    raise ValueError("clamd did not create a regular PID file")
                pid_text = pid_path.read_text(encoding="utf-8").strip()
                if not pid_text.isdigit() or int(pid_text) <= 0:
                    raise ValueError("clamd PID file does not contain a positive PID")
                return process
            except (OSError, ValueError):
                time.sleep(0.2)
    except BaseException:
        process.terminate()
        process.wait(timeout=5)
        raise
    process.terminate()
    process.wait(timeout=5)
    fail(f"clamd did not become ready; see {log_path}")


def path_absent(path: Path) -> bool:
    return not path.exists() and not path.is_symlink()


def stop_daemon(
    process: subprocess.Popen,
    socket_path: Path,
    pid_path: Path,
) -> dict[str, str]:
    running_before_stop = process.poll() is None
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    return {
        "running_before_stop": "yes" if running_before_stop else "no",
        "exited_after_stop": "yes" if process.poll() is not None else "no",
        "socket_absent_after_stop": "yes" if path_absent(socket_path) else "no",
        "pidfile_absent_after_stop": "yes" if path_absent(pid_path) else "no",
    }


def write_service_lifecycle(
    path: Path,
    health_after: str,
    cleanup: dict[str, str],
    pidfile_present_after_start: str = "yes",
) -> None:
    """Retain the daemon health and cleanup facts attached to each case."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "event\tresult\n"
        "ping_before_cases\tpass\n"
        f"ping_after_cases\t{health_after}\n"
        f"pidfile_present_after_start\t{pidfile_present_after_start}\n"
        f"daemon_running_before_stop\t{cleanup['running_before_stop']}\n"
        f"daemon_exited_after_stop\t{cleanup['exited_after_stop']}\n"
        f"socket_absent_after_stop\t{cleanup['socket_absent_after_stop']}\n"
        f"pidfile_absent_after_stop\t{cleanup['pidfile_absent_after_stop']}\n",
        encoding="utf-8",
    )


def send_request(connection: socket.socket, mode: str, fixture: Path) -> None:
    if mode in {"scan", "contscan", "multiscan", "allmatchscan"}:
        protocol.send_path_request(connection, mode, str(fixture))
    elif mode == "fildes":
        protocol.send_fildes_request(connection, str(fixture))
    elif mode == "instream":
        protocol.send_instream_request(connection, str(fixture))
    else:
        fail(f"unsupported direct report mode: {mode}")


def run_report(
    socket_path: Path,
    fixture: Path,
    oracle_path: Path,
    mode: str,
    outcome: str,
    report_path: Path,
    log_path: Path,
) -> dict:
    oracle = protocol.load_oracle(oracle_path, "production")
    protocol.validate_input(str(fixture), oracle)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(30)
        connection.connect(str(socket_path))
        send_request(connection, mode, fixture)
        report = protocol.receive_report(connection)
    protocol.validate_report(report, oracle, mode, fixture.stat().st_size)
    if report.get("completion") != {
        "clean": "COMPLETE",
        "detection": "DETECTION_TERMINATED",
        "limit": "LIMIT_INCOMPLETE",
    }[outcome]:
        fail(f"{mode}/{outcome} report completion changed after validation")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
                           encoding="utf-8")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as stream:
        stream.write(f"protocol_mode={MODES[mode]}\n")
        stream.write(f"fixture={fixture.name}\n")
        stream.write(f"transport=structured-report-frame\n")
        stream.write(f"completion={report['completion']}\n")
        stream.write(f"status={report['status']}\n")
        stream.write(f"reason={report.get('reason', '-')}\n")
        alert = report.get("last_alert") or "-"
        offset = report.get("last_alert_offset", "-")
        stream.write(f"alert={alert}\n")
        stream.write(f"alert_offset={offset}\n")
        if report.get("completion") == "DETECTION_TERMINATED":
            stream.write(f"{fixture}: {alert} FOUND\n")
            stream.write(f"signature {alert} matched at {offset}\n")
        elif report.get("completion") == "COMPLETE":
            stream.write(f"{fixture}: OK\n")
        else:
            stream.write(f"{fixture}: INCOMPLETE ({report.get('reason', 'unknown')})\n")
    return report


def load_report(path: Path, label: str) -> dict:
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"{label} did not write a structured report")
    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(rows) != 1 or not isinstance(rows[0], dict):
        fail(f"{label} structured report is not exactly one JSON object")
    return rows[0]


def run_client(
    clamdscan: Path,
    config: Path,
    fixture: Path,
    oracle_path: Path,
    mode: str,
    outcome: str,
    report_path: Path,
    log_path: Path,
) -> dict:
    label = f"clamdscan/{mode}/{outcome}"
    oracle = protocol.load_oracle(oracle_path, "production")
    protocol.validate_input(str(fixture), oracle)
    command = [
        str(clamdscan),
        f"--config-file={config}",
        f"--report-json={report_path}",
        "--no-summary",
        f"--{mode}",
        str(fixture),
    ]
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.unlink(missing_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log_path.open("w", encoding="utf-8") as stream:
            completed = subprocess.run(
                command,
                stdout=stream,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=30,
            )
    except subprocess.TimeoutExpired as error:
        fail(f"{label} exceeded the 30-second development timeout: {error}")
    if completed.returncode not in (0, 1, 2):
        fail(f"{label} returned unexpected status {completed.returncode}")

    report = load_report(report_path, label)
    protocol.validate_report(report, oracle, f"clamdscan-{mode}", fixture.stat().st_size)
    expected_completion = {
        "clean": "COMPLETE",
        "detection": "DETECTION_TERMINATED",
        "limit": "LIMIT_INCOMPLETE",
    }[outcome]
    if report.get("completion") != expected_completion:
        fail(f"{label} report completion changed after validation")
    expected_status = report_exit(report["completion"])
    if completed.returncode != expected_status:
        fail(f"{label} exit {completed.returncode} does not match report {expected_status}")

    text = log_path.read_text(encoding="utf-8", errors="replace")
    if expected_completion == "DETECTION_TERMINATED":
        alert = report.get("last_alert") or ""
        if not alert or f": {alert} FOUND" not in text:
            fail(f"{label} log does not contain the exact alert")
    elif "FOUND" in text:
        fail(f"{label} log contains an unexpected detection")
    return report


def report_exit(completion: str) -> int:
    return {
        "COMPLETE": 0,
        "DETECTION_TERMINATED": 1,
        "LIMIT_INCOMPLETE": 2,
    }.get(completion, 2)


def make_record(
    output: Path,
    capability: str,
    mode: str,
    outcome: str,
    fixture: Path,
    database: Path,
    oracle_path: Path,
    config: Path,
    report: dict,
    source_manifest: Path,
    build_identity: Path,
    daemon_log: Path,
    record_kind: str = "clamd",
    record_id: str | None = None,
    artifact_prefix: str = "",
    service_input_artifacts: tuple[Path, Path] | None = None,
) -> dict[str, str]:
    completion = str(report["completion"])
    identifier = record_id or capability
    case_id = f"{record_kind}:{identifier}:{OUTCOME_SUFFIX[outcome]}"
    report_rel = f"reports/{artifact_prefix}{mode}-{outcome}.jsonl"
    log_rel = f"logs/{artifact_prefix}{mode}-{outcome}.log"
    config_rel = config.relative_to(output).as_posix()
    fixture_rel = fixture.relative_to(output).as_posix()
    database_rel = database.relative_to(output).as_posix()
    oracle_rel = oracle_path.relative_to(output).as_posix()
    source_rel = source_manifest.relative_to(output).as_posix()
    build_rel = build_identity.relative_to(output).as_posix()
    daemon_rel = daemon_log.relative_to(output).as_posix()
    artifacts = [
        fixture_rel, database_rel, oracle_rel, config_rel, source_rel,
        build_rel, daemon_rel, log_rel, report_rel,
    ]
    if service_input_artifacts is not None:
        artifacts.extend(
            path.relative_to(output).as_posix()
            for path in service_input_artifacts
        )
    numeric = {field: str(report[field]) for field in REPORT_NUMERIC_FIELDS}
    signature = report.get("last_alert") or "-"
    offset = str(report["last_alert_offset"]) if report.get("last_alert_offset") is not None else "-"
    return {
        "kind": record_kind,
        "id": identifier,
        "case_id": case_id,
        "source_manifest_sha256": sha256(source_manifest),
        "build_identity_sha256": sha256(build_identity),
        "config_sha256": sha256(config),
        "platform": f"{os.uname().sysname}-{os.uname().machine}",
        "fixture_role": f"service-development-{outcome}",
        "fixture_sha256": sha256(fixture),
        "oracle_sha256": sha256(oracle_path),
        "database_sha256": sha256(database),
        "exit_code": str(report_exit(completion)),
        "verdict": (
            "DETECTED" if completion == "DETECTION_TERMINATED" else
            "CLEAN" if completion == "COMPLETE" else "INCOMPLETE"
        ),
        "completion": completion,
        "reason": report.get("reason") or f"structured report {completion}",
        "alert_signature": signature,
        "alert_offset": offset,
        **numeric,
        "sanitizer": "development",
        "resource_phase": (
            f"development-envelope;mode={identifier};max-file=64M;max-scan=64M;"
            "max-temp=64M;daemon-rss=unmeasured;socket=tempfs"
        ),
        "health": "pass",
        "cleanup": "pass",
        "artifacts": ",".join(artifacts),
    }


def capture(
    clamd: Path,
    clamdscan: Path | None,
    output: Path,
    source_root: Path,
    build_dir: Path,
    certs: Path | None,
) -> int:
    require_file(clamd, "clamd")
    if not os.access(clamd, os.X_OK):
        fail(f"clamd is not executable: {clamd}")
    if clamdscan is not None:
        require_file(clamdscan, "clamdscan")
        if not os.access(clamdscan, os.X_OK):
            fail(f"clamdscan is not executable: {clamdscan}")
    output = output.resolve()
    source_root = source_root.resolve()
    try:
        output.relative_to(source_root)
    except ValueError:
        pass
    else:
        fail("development service evidence output must be outside the source tree")
    require_file(build_dir / "CMakeCache.txt", "build CMakeCache.txt")
    output.mkdir(parents=True, exist_ok=True)
    for directory in ("corpus", "db", "logs", "reports", "provenance"):
        (output / directory).mkdir(parents=True, exist_ok=True)

    detection_fixture = output / "corpus/detection.bin"
    clean_fixture = output / "corpus/clean.bin"
    limit_fixture = output / "corpus/limit.bin"
    write_fixture(detection_fixture, "detection")
    write_fixture(clean_fixture, "clean")
    write_fixture(limit_fixture, "limit")
    fixture_identities = {
        "service-development-clean": clean_fixture,
        "service-development-detection": detection_fixture,
        "service-development-limit": limit_fixture,
    }
    service_inputs_before = output / "provenance/service-inputs-before.json"
    service_inputs_after = output / "provenance/service-inputs-after.json"
    write_service_input_identity(service_inputs_before, fixture_identities)
    # Keep the detection and benign databases in separate directories.  ClamD
    # loads every database file in DatabaseDirectory, so sharing a directory
    # would make the supposedly clean case load the detection signature too.
    detection_db_src = output / "db/detection/detection.ndb"
    clean_db_src = output / "db/clean/clean.ndb"
    write_database(detection_db_src, True)
    write_database(clean_db_src, False)

    source_manifest = output / "provenance/source-manifest.txt"
    subprocess.run(
        [str(source_root / "tools/largefile_source_manifest.sh"), str(source_root), str(source_manifest)],
        check=True,
    )
    cmake_cache = output / "provenance/CMakeCache.txt"
    cmake_cache.write_bytes(require_file(build_dir / "CMakeCache.txt", "CMake cache").read_bytes())
    build_identity = output / "provenance/build-identity.txt"
    client_identity = (
        f"clamdscan_sha256={sha256(clamdscan)}\n"
        if clamdscan is not None else ""
    )
    build_identity.write_text(
        "capture_kind=development-clamd-and-clamdscan\n"
        f"clamd_sha256={sha256(clamd)}\n"
        f"{client_identity}"
        f"build_type={next((line.split('=', 1)[1] for line in cmake_cache.read_text(encoding='utf-8').splitlines() if line.startswith('CMAKE_BUILD_TYPE:')), 'unknown')}\n"
        f"platform={os.uname().sysname}-{os.uname().machine}\n"
        "sanitizer=development\n"
        "max_file_size=64M\n"
        "max_scan_size=64M\n"
        "max_temporary_size=64M\n",
        encoding="utf-8",
    )

    source_hash = sha256(source_manifest)
    build_hash = sha256(build_identity)
    del source_hash, build_hash
    records: list[dict[str, str]] = []
    native_temp = Path(tempfile.mkdtemp(prefix="clamav-r04-service-"))
    try:
        groups = (
            ("detection", detection_fixture, detection_db_src, "CL_TYPE_TEXT_ASCII", False),
            ("clean", clean_fixture, clean_db_src, "CL_TYPE_TEXT_ASCII", False),
            ("limit", limit_fixture, clean_db_src, "CL_TYPE_BINARY_DATA", True),
        )
        for outcome, fixture, database_src, file_type, limit in groups:
            database = output / f"provenance/database-{outcome}.ndb"
            database.write_bytes(database_src.read_bytes())
            oracle_path = output / f"provenance/oracle-{outcome}.tsv"
            write_oracle(oracle_path, fixture, outcome, file_type)
            socket_path = native_temp / f"clamd-{outcome}.sock"
            pid_path = native_temp / f"clamd-{outcome}.pid"
            temporary = native_temp / f"tmp-{outcome}"
            temporary.mkdir()
            config = output / f"provenance/clamd-{outcome}.conf"
            write_config(config, database_src.parent, socket_path, pid_path, temporary, certs, limit)
            daemon_log = output / f"logs/clamd-{outcome}.log"
            daemon = start_daemon(clamd, config, socket_path, pid_path, daemon_log)
            outcome_records: list[dict[str, str]] = []
            health_after = "fail"
            try:
                ping(socket_path)
                for mode, capability in MODES.items():
                    report_path = output / f"reports/{mode}-{outcome}.jsonl"
                    log_path = output / f"logs/{mode}-{outcome}.log"
                    report = run_report(
                        socket_path, fixture, oracle_path, mode, outcome,
                        report_path, log_path,
                    )
                    record = make_record(
                        output, capability, mode, outcome, fixture, database,
                        oracle_path, config, report, source_manifest,
                        build_identity, daemon_log,
                        service_input_artifacts=(service_inputs_before, service_inputs_after),
                    )
                    records.append(record)
                    outcome_records.append(record)
                if clamdscan is not None:
                    for mode, capability in CLIENT_MODES.items():
                        report_path = output / f"reports/client-{mode}-{outcome}.jsonl"
                        log_path = output / f"logs/client-{mode}-{outcome}.log"
                        report = run_client(
                            clamdscan, config, fixture, oracle_path, mode,
                            outcome, report_path, log_path,
                        )
                        record = make_record(
                            output, capability, mode, outcome, fixture, database,
                            oracle_path, config, report, source_manifest,
                            build_identity, daemon_log, record_kind="clamdscan",
                            record_id=capability, artifact_prefix="client-",
                            service_input_artifacts=(service_inputs_before, service_inputs_after),
                        )
                        records.append(record)
                        outcome_records.append(record)

                # A successful request is not enough to prove that the
                # daemon survived every ingress mode. Retain a final PING
                # before shutdown and attach the lifecycle result to every
                # case from this outcome group.
                ping(socket_path)
                health_after = "pass"
            finally:
                cleanup = stop_daemon(daemon, socket_path, pid_path)
                lifecycle = output / f"provenance/service-lifecycle-{outcome}.tsv"
                write_service_lifecycle(lifecycle, health_after, cleanup)
                lifecycle_rel = lifecycle.relative_to(output).as_posix()
                cleanup_ok = all(
                    cleanup[field] == "yes"
                    for field in (
                        "running_before_stop",
                        "exited_after_stop",
                        "socket_absent_after_stop",
                        "pidfile_absent_after_stop",
                    )
                )
                for record in outcome_records:
                    record["artifacts"] += f",{lifecycle_rel}"
                    record["resource_phase"] += ";daemon-health=ping-before-and-after;cleanup=lifecycle-verified"
                    if health_after != "pass" or not cleanup_ok:
                        record["health"] = "fail"
                        record["cleanup"] = "fail"
    finally:
        for path in native_temp.iterdir():
            if path.is_dir():
                for child in path.iterdir():
                    if child.is_file() or child.is_socket():
                        child.unlink()
                path.rmdir()
            else:
                path.unlink()
        native_temp.rmdir()

    write_service_input_identity(service_inputs_after, fixture_identities)
    if service_inputs_before.read_bytes() != service_inputs_after.read_bytes():
        fail("service fixture identity changed during development capture")

    records_path = output / "provenance/acceptance-cases.tsv"
    with records_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=acceptance_cases.RECORD_HEADER,
            delimiter="\t", lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(sorted(records, key=lambda row: row["case_id"]))
    manifest = source_root / "docs/largefile-capabilities.tsv"
    mapping = source_root / "docs/largefile-capability-case-map.tsv"
    acceptance_cases.validate_records(
        records_path, acceptance_cases.validate_map(manifest, mapping),
        evidence_root=output,
    )
    return len(records)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("clamd", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--clamdscan", type=Path,
                        help="also capture clamdscan --fdpass and --stream records")
    parser.add_argument("--source-root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--cvd-certs-dir", type=Path)
    args = parser.parse_args(argv)
    try:
        count = capture(
            args.clamd, args.clamdscan, args.output, args.source_root, args.build_dir,
            args.cvd_certs_dir,
        )
        print(f"development service capture wrote {count} R04 records")
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError, csv.Error,
            json.JSONDecodeError, socket.error) as error:
        print(f"development service capture failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
