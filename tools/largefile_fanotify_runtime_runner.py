#!/usr/bin/env python3
"""Run one real R13 fanotify case and retain bindable evidence.

This runner is deliberately one-case-per-invocation.  A coordinator supplies
the exact fixture, build, database, mount, and output paths, then invokes it
once for each reviewed R13 prevention case.  It starts the real clamd and
clamonacc binaries, runs the repository's independent fanotify observer (or a
monitoring-only actor), retains process health and cleanup facts, and binds
prevention artifacts with ``largefile_fanotify_case_binder.py``.  It never
fabricates a kernel event, actor result, permission decision, or scan report.

The command is intended for an already-authorized Linux runtime, normally a
disposable privileged container.  It does not create mounts or install
dependencies; the caller owns the mount lifecycle and passes its mount path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

sys.dont_write_bytecode = True
TOOLS_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS_ROOT))
import largefile_acceptance_cases as acceptance_cases
import largefile_fanotify_case_binder as case_binder


CASES = ("clean", "detection", "limit", "resource", "timeout", "parser")
REPORT_EVENT_KIND = "clamonacc-permission-decision"


class RunnerError(RuntimeError):
    """A fail-visible runtime runner error."""


def fail(message: str) -> None:
    raise RunnerError(message)


def require_file(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} is missing, symlinked, or not a regular file: {path}")
    return path.resolve()


def require_directory(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        fail(f"{label} is missing, symlinked, or symlinked: {path}")
    return path.resolve()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_text(path: Path, content: str) -> None:
    if path.exists() or path.is_symlink():
        fail(f"runner refuses to overwrite existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def parse_option(value: str) -> tuple[str, str]:
    name, separator, setting = value.partition("=")
    if not separator or not name or not setting or any(char.isspace() for char in name):
        fail(f"--clamd-option must be NAME=VALUE: {value!r}")
    if name in {"DatabaseDirectory", "LocalSocket", "PidFile", "TemporaryDirectory",
                "OnAccessIncludePath", "CVDCertsDirectory"}:
        fail(f"--clamd-option cannot override runner-owned option: {name}")
    return name, setting


def write_config(
    path: Path,
    database: Path,
    socket_path: Path,
    pid_path: Path,
    temporary: Path,
    mount_path: Path,
    prevention: bool,
    cvd_certs: Path | None,
    args: argparse.Namespace,
) -> list[str]:
    lines = [
        f"DatabaseDirectory {database}",
        f"LocalSocket {socket_path}",
        f"PidFile {pid_path}",
        f"TemporaryDirectory {temporary}",
        "MaxThreads 1",
        "MaxQueue 2",
        f"MaxFileSize {args.max_file_size}",
        f"MaxScanSize {args.max_scan_size}",
        f"MaxTemporarySize {args.max_temporary_size}",
        f"MaxScanTime {args.max_scan_time}",
        "MaxMatcherWork 256G",
        "MaxContiguousSize 32G",
        "PCREMaxFileSize 32G",
        "StreamMaxLength 32G",
        "MaxRecursion 17",
        "MaxFiles 10000",
        "AlertExceedsMax yes",
        "Foreground yes",
        "Debug yes",
        "LogVerbose yes",
        f"OnAccessIncludePath {mount_path}",
        "OnAccessExcludeRootUID yes",
        "OnAccessMaxThreads 1",
        f"OnAccessPrevention {'yes' if prevention else 'no'}",
    ]
    if cvd_certs is not None:
        lines.insert(1, f"CVDCertsDirectory {cvd_certs}")
    for option in args.clamd_option:
        name, setting = parse_option(option)
        lines.append(f"{name} {setting}")
    write_text(path, "\n".join(lines) + "\n")
    return lines


def ping(socket_path: Path, timeout_seconds: float = 2.0) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout_seconds)
        connection.connect(str(socket_path))
        connection.sendall(b"zPING\x00")
        reply = connection.recv(5)
    if reply != b"PONG\x00":
        fail(f"clamd returned an invalid PING reply: {reply!r}")


def wait_for_daemon(
    process: subprocess.Popen, socket_path: Path, timeout: float, log_path: Path,
) -> None:
    deadline = time.monotonic() + timeout
    last_error = "socket not ready"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            detail = log_path.read_text(encoding="utf-8", errors="replace")[-4096:]
            fail(
                f"clamd exited before readiness with status {process.returncode}; "
                f"log tail: {detail.strip()}"
            )
        try:
            ping(socket_path)
            return
        except (OSError, RunnerError) as error:
            last_error = str(error)
            time.sleep(0.1)
    fail(f"clamd did not become ready: {last_error}")


def stop_process(process: subprocess.Popen | None, name: str) -> dict[str, object]:
    if process is None:
        return {"started": False, "alive_after_cleanup": False, "exit_code": None}
    was_alive = process.poll() is None
    if was_alive:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    result = {
        "name": name,
        "started": True,
        "alive_after_cleanup": process.poll() is None,
        "exit_code": process.returncode,
    }
    if result["alive_after_cleanup"]:
        fail(f"{name} remained alive after cleanup")
    return result


def actor_command(fixture: Path, uid: int) -> list[str]:
    code = (
        "import json,sys\n"
        "try:\n"
        "    with open(sys.argv[1], 'rb') as stream:\n"
        "        stream.read(1)\n"
        "except OSError as error:\n"
        "    print(json.dumps({'opened':False,'errno':error.errno}), flush=True)\n"
        "    raise SystemExit(1)\n"
        "else:\n"
        "    print(json.dumps({'opened':True}), flush=True)\n"
    )
    return [sys.executable, "-c", code, str(fixture)]


def actor_preexec(uid: int) -> None:
    import pwd

    account = pwd.getpwuid(uid)
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(uid)


def start_actor(fixture: Path, uid: int, output: Path) -> subprocess.Popen[str]:
    if uid <= 0 or uid > 65535:
        fail("actor UID must be a non-root value between 1 and 65535")
    with output.open("w", encoding="utf-8") as stream:
        return subprocess.Popen(
            actor_command(fixture, uid),
            stdin=subprocess.DEVNULL,
            stdout=stream,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=True,
            start_new_session=True,
            preexec_fn=lambda: actor_preexec(uid),
        )


def load_json_lines(path: Path, label: str) -> list[dict[str, object]]:
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            rows.append(acceptance_cases.load_json_object(line, f"{label} line {number}"))
    if not rows:
        fail(f"{label} is empty")
    return rows


def select_permission_event_id(path: Path) -> int:
    rows = load_json_lines(path, "clamonacc permission evidence")
    candidates = [
        row for row in rows
        if row.get("artifact_kind") == REPORT_EVENT_KIND
        and row.get("event_kind") == "FAN_OPEN_PERM"
        and type(row.get("clamonacc_event_id")) is int
    ]
    if not candidates:
        fail("clamonacc permission evidence has no permission event")
    return int(candidates[0]["clamonacc_event_id"])


def select_report(path: Path, event_id: int, output: Path) -> None:
    reports = load_json_lines(path, "clamonacc report evidence")
    matches = [row for row in reports if row.get("clamonacc_event_id") == event_id]
    if len(matches) != 1:
        fail(f"structured report has {len(matches)} records for event {event_id}")
    write_text(output, json.dumps(matches[0], sort_keys=True) + "\n")


def run_case(args: argparse.Namespace) -> dict[str, object]:
    source_root = require_directory(args.source_root, "source root")
    mount_path = require_directory(args.mount_path, "mount path")
    fixture = require_file(args.fixture, "fixture")
    try:
        fixture.relative_to(mount_path)
    except ValueError as error:
        raise RunnerError("fixture must be inside the supplied mount path") from error
    if args.case_name not in CASES:
        fail(f"unknown R13 case: {args.case_name}")
    if args.monitoring_only and args.case_name not in CASES:
        fail("monitoring-only case is invalid")
    if args.output_root.exists():
        fail(f"output root already exists; runner refuses to overwrite: {args.output_root}")
    output_root = args.output_root.resolve()
    output_root.mkdir(parents=True)
    logs = output_root / "logs"
    reports = output_root / "reports"
    raw = output_root / "raw"
    bound = output_root / "bound"
    for directory in (logs, reports, raw, bound):
        directory.mkdir()

    database = require_directory(args.database_directory, "database directory")
    cvd_certs = require_directory(args.cvd_certs_dir, "CVD certificate directory") if args.cvd_certs_dir else None
    clamd = require_file(args.clamd, "clamd")
    clamonacc = require_file(args.clamonacc, "clamonacc")
    temporary = output_root / "temporary"
    temporary.mkdir()
    socket_path = output_root / "clamd.sock"
    pid_path = output_root / "clamd.pid"
    config_path = output_root / "clamd.conf"
    config_lines = write_config(
        config_path, database, socket_path, pid_path, temporary, mount_path,
        not args.monitoring_only, cvd_certs, args,
    )
    fixture_hash = sha256(fixture)
    clamd_log = logs / "clamd.log"
    clamonacc_log = logs / "clamonacc.log"
    permission_path = raw / "clamonacc-permission.jsonl"
    report_path = raw / "clamonacc-report.jsonl"
    observer_kernel = raw / "observer-kernel.jsonl"
    observer_actor = raw / "observer-actor.json"
    clamd_process = None
    clamonacc_process = None
    observer_process = None
    actor_process = None
    health: dict[str, object] = {}
    cleanup: dict[str, object] = {}
    started = time.time_ns()
    try:
        with clamd_log.open("w", encoding="utf-8") as stream:
            clamd_process = subprocess.Popen(
                [str(clamd), f"--config-file={config_path}"],
                stdout=stream, stderr=subprocess.STDOUT,
            )
        wait_for_daemon(clamd_process, socket_path, args.startup_timeout, clamd_log)
        health["clamd_startup_pong"] = True
        with clamonacc_log.open("w", encoding="utf-8") as stream:
            clamonacc_process = subprocess.Popen(
                [str(clamonacc), "--config-file", str(config_path), "--foreground",
                 f"--report-json={report_path}",
                 f"--fanotify-evidence={permission_path}",
                 f"--log={clamonacc_log}"],
                stdout=stream, stderr=subprocess.STDOUT,
            )
        time.sleep(1.0)
        if clamonacc_process.poll() is not None:
            detail = clamonacc_log.read_text(encoding="utf-8", errors="replace")[-4096:]
            fail(
                f"clamonacc exited before the actor with status {clamonacc_process.returncode}; "
                f"log tail: {detail.strip()}"
            )
        health["clamonacc_alive_before_actor"] = True
        if args.monitoring_only:
            actor_process = start_actor(fixture, args.actor_uid, raw / "monitor-actor.json")
        else:
            observer = source_root / "tools" / "largefile_fanotify_capture.py"
            observer_process = subprocess.Popen([
                sys.executable, "-B", str(observer),
                "--mount-path", str(mount_path), "--fixture", str(fixture),
                "--kernel-event-artifact", str(observer_kernel),
                "--actor-result-artifact", str(observer_actor),
                "--fixture-sha256", fixture_hash,
                "--actor-uid", str(args.actor_uid), "--case-name", args.case_name,
                "--timeout-seconds", str(args.actor_timeout),
            ], stdout=(logs / "observer.log").open("w", encoding="utf-8"),
               stderr=subprocess.STDOUT)
            observer_status = observer_process.wait(timeout=args.actor_timeout + 10)
            if observer_status != 0:
                fail(f"fanotify observer exited with status {observer_status}")
        if actor_process is not None:
            actor_process.wait(timeout=args.actor_timeout + 10)
        time.sleep(1.0)
        health["clamd_pre_cleanup_pong"] = True
        ping(socket_path)
    finally:
        cleanup["observer"] = stop_process(observer_process, "fanotify observer")
        cleanup["actor"] = stop_process(actor_process, "monitoring actor")
        cleanup["clamonacc"] = stop_process(clamonacc_process, "clamonacc")
        cleanup["clamd"] = stop_process(clamd_process, "clamd")
        cleanup["socket_absent"] = not socket_path.exists()
        cleanup["pid_absent"] = not pid_path.exists()
        cleanup["complete"] = bool(cleanup["socket_absent"] and cleanup["pid_absent"])
    if not cleanup["complete"]:
        fail("runtime cleanup left a socket or PID file behind")

    if args.monitoring_only:
        monitor_actor = raw / "monitor-actor.json"
        if not monitor_actor.is_file() or not report_path.is_file():
            fail("monitoring-only run did not retain actor and report artifacts")
        result = {
            "case_name": args.case_name,
            "mode": "monitoring-only",
            "fixture_sha256": fixture_hash,
            "report": str(report_path.relative_to(output_root)),
            "actor": str(monitor_actor.relative_to(output_root)),
        }
    else:
        event_id = select_permission_event_id(permission_path)
        selected_report = raw / "clamonacc-report-target.jsonl"
        select_report(report_path, event_id, selected_report)
        bound_result = case_binder.bind(
            args.case_name, fixture_hash, observer_kernel, permission_path,
            observer_actor, selected_report, bound / "kernel-event.jsonl",
            bound / "actor-result.jsonl", bound / "scan-report.jsonl",
        )
        result = {"case_name": args.case_name, "mode": "prevention", **bound_result}

    provenance = {
        "source_root": str(source_root),
        "source_manifest_sha256": sha256(args.source_manifest) if args.source_manifest else None,
        "build_identity": str(args.build_identity) if args.build_identity else None,
        "clamd": str(clamd),
        "clamonacc": str(clamonacc),
        "fixture": str(fixture),
        "fixture_sha256": fixture_hash,
        "config_sha256": sha256(config_path),
        "config": config_lines,
        "started_unix_ns": started,
        "finished_unix_ns": time.time_ns(),
    }
    write_text(output_root / "provenance.json", json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    write_text(output_root / "health-cleanup.json", json.dumps({"health": health, "cleanup": cleanup}, indent=2, sort_keys=True) + "\n")
    write_text(output_root / "result.json", json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--clamd", type=Path, required=True)
    parser.add_argument("--clamonacc", type=Path, required=True)
    parser.add_argument("--database-directory", type=Path, required=True)
    parser.add_argument("--cvd-certs-dir", type=Path)
    parser.add_argument("--mount-path", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--case-name", choices=CASES, required=True)
    parser.add_argument("--monitoring-only", action="store_true")
    parser.add_argument("--actor-uid", type=int, default=65534)
    parser.add_argument("--startup-timeout", type=float, default=30.0)
    parser.add_argument("--actor-timeout", type=float, default=60.0)
    parser.add_argument("--max-file-size", default="32G")
    parser.add_argument("--max-scan-size", default="64G")
    parser.add_argument("--max-temporary-size", default="64G")
    parser.add_argument("--max-scan-time", default="60000")
    parser.add_argument("--clamd-option", action="append", default=[])
    parser.add_argument("--source-manifest", type=Path)
    parser.add_argument("--build-identity", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        result = run_case(parse_args(argv))
    except (OSError, RunnerError, subprocess.SubprocessError, ValueError, KeyError) as error:
        print(f"large-file fanotify runtime runner failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
