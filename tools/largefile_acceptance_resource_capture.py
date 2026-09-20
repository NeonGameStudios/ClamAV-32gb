#!/usr/bin/env python3
"""Capture an independently sampled resource row for one acceptance case.

The wrapped command is sampled while it is alive.  RSS/PSS/VAS, swap, faults,
I/O, OOM counters, and temporary-tree size come from separate fail-closed
samplers; no budget value is copied into the result.  A PCRE-aware command may
write the phase protocol named by ``CLAMAV_LARGEFILE_RESOURCE_PHASE_FILE``:
``pcre-start``, ``post-pcre``, and ``complete``.  PCRE rows are rejected
unless both phase peaks were actually sampled.

The command's exit status is returned after a successful resource row is
written.  This lets callers preserve acceptance outcomes such as malformed,
limit, or application-failure cases while still requiring resource evidence.
"""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from queue import Empty, Queue

sys.path.insert(0, str(Path(__file__).resolve().parent))
import largefile_acceptance_resources as resources


ROOT = Path(__file__).resolve().parent
METRICS_TOOL = ROOT / "largefile_procfs_tree_metrics.py"
OOM_TOOL = ROOT / "largefile_procfs_tree_oom.py"
METRIC_FIELDS = (
    "rss_peak_kb", "pss_peak_kb", "vas_peak_kb", "swap_peak_kb",
    "minor_faults_peak", "major_faults_peak", "read_bytes_peak",
    "write_bytes_peak", "cancelled_write_bytes_peak",
)
PHASE_EVENTS = {"pcre-start", "post-pcre", "deep-parse", "complete"}
PHASE_SAMPLE_LABELS = {
    "pcre-start": "pcre",
    "post-pcre": "post-pcre",
    "deep-parse": "deep-parse",
}
POST_PCRE_RSS_BUDGET_KB = 12582912
POST_PCRE_RELEASE_WAIT_SECONDS = 20.0
SAFE_CASE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


class CaptureError(ValueError):
    """A fail-closed capture error."""


def fail(message: str) -> None:
    raise CaptureError(message)


def path_under(root: Path, raw: Path, label: str) -> Path:
    candidate = raw if raw.is_absolute() else root / raw
    candidate = candidate.absolute()
    if candidate.is_symlink():
        fail(f"{label} is symlinked: {candidate}")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise CaptureError(f"{label} escapes the evidence root: {candidate}") from error
    return resolved


def require_artifact(root: Path, raw: Path, label: str) -> Path:
    path = path_under(root, raw, label)
    if not path.is_file():
        fail(f"{label} is missing: {path}")
    return path


def temporary_size(path: Path) -> int:
    if path.is_symlink() or not path.is_dir():
        fail(f"temporary root is missing, not a directory, or symlinked: {path}")
    total = 0
    try:
        entries = list(os.scandir(path))
    except OSError as error:
        raise CaptureError(f"cannot enumerate temporary root {path}: {error}") from error
    for entry in entries:
        entry_path = Path(entry.path)
        if entry.is_symlink():
            fail(f"temporary tree contains a symlink: {entry_path}")
        if entry.is_dir(follow_symlinks=False):
            total += temporary_size(entry_path)
        elif entry.is_file(follow_symlinks=False):
            try:
                total += entry.stat(follow_symlinks=False).st_size
            except OSError as error:
                raise CaptureError(f"cannot stat temporary file {entry_path}: {error}") from error
        else:
            fail(f"temporary tree contains an unsupported entry: {entry_path}")
    return total


def run_sampler(tool: Path, pid: int, include_root: bool = False) -> list[str]:
    try:
        command = [sys.executable, str(tool)]
        if include_root:
            command.append("--include-root")
        command.append(str(pid))
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CaptureError(f"resource sampler could not run: {tool}: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip() or "sampler returned no diagnostic"
        raise CaptureError(f"resource sampler failed: {tool.name}: {detail}")
    lines = result.stdout.splitlines()
    if len(lines) != 1:
        fail(f"resource sampler returned an invalid row count: {tool.name}")
    return lines[0].split("\t")


def metric_sample(pid: int) -> dict[str, int]:
    fields = run_sampler(METRICS_TOOL, pid, include_root=True)
    if len(fields) != 12 or any(not value.isdigit() for value in fields[:11]):
        fail("process-tree resource sampler returned an invalid metric row")
    return dict(zip(
        (
            "root_rss_kb", "rss_kb", "pss_kb", "vas_kb", "swap_kb",
            "minor_faults", "major_faults", "read_bytes", "write_bytes",
            "cancelled_write_bytes", "process_count",
        ),
        (int(value) for value in fields[:11]),
    ))


def append_sample_trace(
    stream: object,
    sequence: int,
    phase: str,
    rss_kb: int,
    tree_rss_kb: int,
    process_count: int,
) -> None:
    """Write one ordered, timestamped process-tree sample."""
    if sequence < 1 or phase not in {
        "before-pcre", "pcre", "post-pcre-before-deep-parse", "deep-parse",
    }:
        fail("sample trace has an invalid sequence or phase")
    if rss_kb < 0 or tree_rss_kb < rss_kb or process_count < 1:
        fail("sample trace has invalid resource values")
    try:
        stream.write(
            f"{sequence}\t{time.time_ns()}\t{phase}\t{rss_kb}\t"
            f"{tree_rss_kb}\t{process_count}\n"
        )
        stream.flush()
    except (AttributeError, OSError) as error:
        raise CaptureError(f"cannot write process sample trace: {error}") from error


def oom_sample(pid: int) -> dict[str, str | int]:
    fields = run_sampler(OOM_TOOL, pid)
    if len(fields) != 4 or any(not value.isdigit() for value in fields[:3]):
        fail("process-tree OOM sampler returned an invalid row")
    if not re.fullmatch(r"[0-9a-f]{64}", fields[3]):
        fail("process-tree OOM sampler returned an invalid cgroup digest")
    return {
        "oom_events": int(fields[0]),
        "oom_kill_events": int(fields[1]),
        "oom_cgroup_count": int(fields[2]),
        "oom_cgroup_digest": fields[3],
    }


def phase_events(path: Path) -> list[str]:
    if path.is_symlink():
        fail(f"phase protocol is symlinked: {path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise CaptureError(f"cannot read phase protocol {path}: {error}") from error
    events: list[str] = []
    state = "pre-pcre"
    for line_number, line in enumerate(lines, start=1):
        event = line.strip()
        if not event:
            continue
        if event not in PHASE_EVENTS:
            fail(f"phase protocol has an unknown event at line {line_number}: {event}")
        if event == "pcre-start":
            if state not in {"pre-pcre", "pcre"}:
                fail(f"phase protocol starts PCRE after post-PCRE at line {line_number}")
            state = "pcre"
        elif event == "post-pcre":
            if state not in {"pcre", "post-pcre"}:
                fail(f"phase protocol enters post-PCRE without PCRE at line {line_number}")
            state = "post-pcre"
        elif event == "deep-parse":
            if state not in {"post-pcre", "deep-parse"}:
                fail(f"phase protocol enters deep parse before post-PCRE at line {line_number}")
            state = "deep-parse"
        else:
            state = "complete"
        events.append(event)
    return events


def phase_state(path: Path) -> str:
    state = "pre-pcre"
    for event in phase_events(path):
        if event == "pcre-start":
            state = "pcre"
        elif event == "post-pcre":
            state = "post-pcre"
        elif event == "deep-parse":
            state = "deep-parse"
        else:
            state = "complete"
    return state


def append_phase_event(path: Path, event: str) -> None:
    """Append one terminal phase event without following a replacement symlink."""
    if event not in PHASE_EVENTS:
        fail(f"unknown phase event: {event}")
    if path.is_symlink():
        fail(f"phase protocol is symlinked: {path}")
    flags = os.O_WRONLY | os.O_APPEND
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags | nofollow)
    except OSError as error:
        raise CaptureError(f"cannot append phase protocol {path}: {error}") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            fail(f"phase protocol is not a regular file: {path}")
        payload = f"{event}\n".encode("ascii")
        offset = 0
        while offset < len(payload):
            try:
                written = os.write(descriptor, payload[offset:])
            except InterruptedError:
                continue
            if written <= 0:
                fail(f"phase protocol write made no progress: {path}")
            offset += written
    except OSError as error:
        raise CaptureError(f"cannot write phase protocol {path}: {error}") from error
    finally:
        os.close(descriptor)


def record_sample_measurement(
    metric: dict[str, int],
    oom: dict[str, str | int],
    temporary_bytes: int,
    state: str,
    baseline_oom: dict[str, str | int],
    current: dict[str, int],
    phase_peaks: dict[str, int | None],
    sample_trace: object | None = None,
) -> dict[str, int | str]:
    for key in ("oom_events", "oom_kill_events"):
        if int(oom[key]) < int(baseline_oom[key]):
            fail(f"OOM counter decreased during capture: {key}")
        current_key = f"{key}_peak"
        delta = int(oom[key]) - int(baseline_oom[key])
        current[current_key] = max(current[current_key], delta)
    if oom["oom_cgroup_count"] < 1:
        fail("OOM sampler returned no cgroup")
    if oom["oom_cgroup_digest"] != baseline_oom["oom_cgroup_digest"]:
        fail("OOM cgroup identity changed during capture")
    current["oom_cgroup_count"] = int(oom["oom_cgroup_count"])
    current["oom_cgroup_digest"] = str(oom["oom_cgroup_digest"])

    for source, destination in (
        ("rss_kb", "rss_peak_kb"), ("pss_kb", "pss_peak_kb"),
        ("vas_kb", "vas_peak_kb"), ("swap_kb", "swap_peak_kb"),
        ("minor_faults", "minor_faults_peak"),
        ("major_faults", "major_faults_peak"),
        ("read_bytes", "read_bytes_peak"),
        ("write_bytes", "write_bytes_peak"),
        ("cancelled_write_bytes", "cancelled_write_bytes_peak"),
    ):
        current[destination] = max(current[destination], metric[source])
    current["temporary_peak_bytes"] = max(current["temporary_peak_bytes"], temporary_bytes)

    if state not in {"pre-pcre", "pcre", "post-pcre", "deep-parse", "complete"}:
        fail(f"sample has an invalid phase: {state}")
    # The application writes post-pcre immediately after releasing the full
    # subject, but Linux may take a short interval to reclaim the unlocked
    # pages.  Keep those transitional samples in the PCRE peak and do not
    # acknowledge the application boundary until the independent sampler has
    # observed the required post-release headroom.
    if state == "post-pcre" and metric["rss_kb"] >= POST_PCRE_RSS_BUDGET_KB:
        state = "pcre"
    phase_rss_key = {
        "pcre": "pcre_rss_peak_kb",
        "post-pcre": "post_pcre_rss_peak_kb",
    }.get(state)
    if phase_rss_key:
        phase_peaks[phase_rss_key] = max(
            int(phase_peaks[phase_rss_key] or 0), metric["rss_kb"]
        )
    if sample_trace is not None:
        sample_phase = {
            "pre-pcre": "before-pcre",
            "pcre": "pcre",
            "post-pcre": "post-pcre-before-deep-parse",
            "deep-parse": "deep-parse",
        }.get(state)
        # ``complete`` is a terminal wrapper event, not an application
        # phase.  In particular, a detection may terminate before parser
        # dispatch, so mapping completion to ``deep-parse`` would fabricate
        # the phase that R13 requires the application to emit and the
        # independent sampler to observe.
        if sample_phase is None:
            return current
        append_sample_trace(
            sample_trace,
            int(current["sample_count"]) + 1,
            sample_phase,
            metric["root_rss_kb"],
            metric["rss_kb"],
            metric["process_count"],
        )
    return current


def sample_row(
    pid: int,
    temporary_root: Path,
    phase_file: Path,
    baseline_oom: dict[str, str | int],
    current: dict[str, int],
    phase_peaks: dict[str, int | None],
    sample_trace: object | None = None,
    phase_override: str | None = None,
) -> dict[str, int | str]:
    metric = metric_sample(pid)
    oom = oom_sample(pid)
    return record_sample_measurement(
        metric,
        oom,
        temporary_size(temporary_root),
        phase_override or phase_state(phase_file),
        baseline_oom,
        current,
        phase_peaks,
        sample_trace,
    )


def phase_event_sample(
    event: str,
    pid: int,
    temporary_root: Path,
    phase_file: Path,
    baseline_oom: dict[str, str | int],
    current: dict[str, int],
    phase_peaks: dict[str, int | None],
    sample_trace: object | None = None,
) -> dict[str, int | str]:
    """Capture one external procfs snapshot for an observed runtime event."""
    label = PHASE_SAMPLE_LABELS.get(event)
    if label is None:
        return current
    return sample_row(
        pid,
        temporary_root,
        phase_file,
        baseline_oom,
        current,
        phase_peaks,
        sample_trace,
        phase_override=label,
    )


def phase_event_measurement(
    event: str,
    pid: int,
    baseline_oom: dict[str, str | int],
    ack_file: Path,
) -> tuple[str, dict[str, int], dict[str, str | int], int] | None:
    """Take the metric snapshot for a phase event without sharing sampler state."""
    label = PHASE_SAMPLE_LABELS.get(event)
    if label is None:
        return None
    # The phase boundary needs an independent RSS/tree snapshot.  For
    # post-PCRE, wait for the actual process-tree RSS to fall below the
    # contract before acknowledging the application.  This preserves the
    # ordering guarantee: deep parsing cannot begin until the independent
    # sampler has observed the required headroom.
    deadline = time.monotonic() + POST_PCRE_RELEASE_WAIT_SECONDS
    while True:
        metric = metric_sample(pid)
        if label != "post-pcre" or metric["rss_kb"] < POST_PCRE_RSS_BUDGET_KB:
            break
        if time.monotonic() >= deadline:
            fail("post-PCRE RSS did not fall below the 12 GiB budget before acknowledgement")
        time.sleep(0.01)
    measurement = (
        label,
        metric,
        dict(baseline_oom),
        0,
    )
    write_phase_ack(ack_file, event)
    return measurement


def write_phase_ack(path: Path, event: str) -> None:
    """Release one opt-in scanner phase rendezvous after sampling it."""
    if path.is_symlink():
        fail(f"phase acknowledgement is symlinked: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags | nofollow, 0o600)
        try:
            payload = f"{event}\n".encode("ascii")
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    fail(f"phase acknowledgement write made no progress: {path}")
                offset += written
        finally:
            os.close(descriptor)
    except OSError as error:
        raise CaptureError(f"cannot write phase acknowledgement {path}: {error}") from error


def drain_phase_measurements(
    measurements: Queue[tuple[str, dict[str, int], dict[str, str | int], int]],
    baseline_oom: dict[str, str | int],
    current: dict[str, int],
    phase_peaks: dict[str, int | None],
    sample_trace: object | None,
    sample_lock: threading.Lock,
) -> None:
    """Merge event snapshots after the watcher has sampled them independently."""
    while True:
        try:
            state, metric, oom, temporary_bytes = measurements.get_nowait()
        except Empty:
            return
        with sample_lock:
            record_sample_measurement(
                metric,
                oom,
                temporary_bytes,
                state,
                baseline_oom,
                current,
                phase_peaks,
                sample_trace,
            )
            current["sample_count"] = int(current["sample_count"]) + 1


def watch_phase_events(
    process: subprocess.Popen[object],
    phase_file: Path,
    temporary_root: Path,
    baseline_oom: dict[str, str | int],
    measurements: Queue[tuple[str, dict[str, int], dict[str, str | int], int]],
    ack_file: Path,
    stop: threading.Event,
    errors: list[CaptureError],
) -> None:
    """Observe phase writes while the regular sampler is collecting metrics."""
    seen = 0
    while not stop.is_set():
        try:
            events = phase_events(phase_file)
            if len(events) < seen:
                fail("phase protocol was truncated while capture was live")
            new_events = events[seen:]
            seen = len(events)
            for event in new_events:
                try:
                    measurement = phase_event_measurement(
                        event, process.pid, baseline_oom, ack_file
                    )
                except CaptureError as error:
                    # Do not strand the scanner at an opt-in rendezvous when
                    # the independent sampler itself fails; the capture then
                    # fails closed after the command exits.
                    if event in PHASE_SAMPLE_LABELS:
                        try:
                            write_phase_ack(ack_file, event)
                        except CaptureError as ack_error:
                            errors.append(ack_error)
                    errors.append(error)
                    return
                if measurement is not None:
                    measurements.put(measurement)
        except CaptureError as error:
            errors.append(error)
            return
        if process.poll() is not None:
            return
        stop.wait(0.001)


def append_row(path: Path, row: dict[str, int | str], root: Path) -> None:
    path = path_under(root, path, "resource sidecar")
    if path.exists() and path.is_symlink():
        fail(f"resource sidecar is symlinked: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, str]] = []
    if path.exists():
        rows = resources.read_resources(path)
        key = (str(row["kind"]), str(row["id"]), str(row["case_id"]))
        if any((item["kind"], item["id"], item["case_id"]) == key for item in rows):
            fail(f"resource sidecar already contains case: {':'.join(key)}")
    rows.append({field: str(row[field]) for field in resources.RESOURCE_HEADER})
    staging = path.with_name(f".{path.name}.capture-staging")
    try:
        with staging.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream, fieldnames=resources.RESOURCE_HEADER,
                delimiter="\t", lineterminator="\n",
            )
            writer.writeheader()
            writer.writerows(rows)
        os.replace(staging, path)
    finally:
        if staging.exists():
            staging.unlink()


def terminate_child(process: subprocess.Popen[object]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass


def capture(args: argparse.Namespace) -> int:
    root = args.evidence_root.resolve()
    if not root.is_dir():
        fail(f"evidence root is not a directory: {root}")
    source = require_artifact(root, args.source_manifest, "source manifest")
    build = require_artifact(root, args.build_identity, "build identity")
    config = require_artifact(root, args.config, "configuration artifact")
    temporary_root = path_under(root, args.temporary_root, "temporary root")
    if temporary_root == root:
        fail("temporary root must not be the evidence root")
    if temporary_root.is_symlink() or not temporary_root.is_dir():
        fail(f"temporary root is missing or not a directory: {temporary_root}")
    output = path_under(root, args.output, "resource sidecar")
    safe_case = SAFE_CASE_RE.sub("_", args.case_id).strip("._") or "case"
    phase_file = path_under(
        root,
        args.phase_file or Path("provenance") / f"acceptance-case-{safe_case}.phase",
        "phase protocol",
    )
    if phase_file.exists() and phase_file.is_symlink():
        fail(f"phase protocol is symlinked: {phase_file}")
    if phase_file.exists() and phase_file.stat().st_size:
        fail(f"phase protocol already contains data: {phase_file}")
    phase_file.parent.mkdir(parents=True, exist_ok=True)
    phase_file.write_text("", encoding="utf-8")
    phase_ack_file = path_under(
        root,
        phase_file.with_name(f".{phase_file.name}.ack"),
        "phase acknowledgement",
    )
    if phase_ack_file.exists():
        if phase_ack_file.is_symlink():
            fail(f"phase acknowledgement is symlinked: {phase_ack_file}")
        fail(f"phase acknowledgement already exists: {phase_ack_file}")

    process_log: Path | None = None
    process_log_stream = None
    requested_process_log = getattr(args, "process_log", None)
    if requested_process_log is not None:
        process_log = path_under(root, requested_process_log, "process log")
        if process_log.exists() and process_log.is_symlink():
            fail(f"process log is symlinked: {process_log}")
        if process_log.exists() and process_log.stat().st_size:
            fail(f"process log already contains data: {process_log}")
        process_log.parent.mkdir(parents=True, exist_ok=True)
        process_log_stream = process_log.open("wb")

    sample_trace: Path | None = None
    sample_trace_stream = None
    requested_sample_trace = getattr(args, "sample_log", None)
    if requested_sample_trace is not None:
        sample_trace = path_under(root, requested_sample_trace, "sample trace")
        if sample_trace.exists() and sample_trace.is_symlink():
            if process_log_stream is not None:
                process_log_stream.close()
            fail(f"sample trace is symlinked: {sample_trace}")
        if sample_trace.exists() and sample_trace.stat().st_size:
            if process_log_stream is not None:
                process_log_stream.close()
            fail(f"sample trace already contains data: {sample_trace}")
        sample_trace.parent.mkdir(parents=True, exist_ok=True)
        sample_trace_stream = sample_trace.open("w", encoding="utf-8")
        sample_trace_stream.write(
            "sequence\ttimestamp_ns\tphase\trss_kb\ttree_rss_kb\tprocess_count\n"
        )
        sample_trace_stream.flush()

    def close_capture_streams() -> None:
        for stream in (process_log_stream, sample_trace_stream):
            if stream is not None and not stream.closed:
                stream.close()

    def cleanup_phase_ack() -> None:
        if phase_ack_file.is_symlink():
            fail(f"phase acknowledgement is symlinked: {phase_ack_file}")
        try:
            phase_ack_file.unlink()
        except FileNotFoundError:
            pass

    environment = os.environ.copy()
    environment["CLAMAV_LARGEFILE_RESOURCE_PHASE_FILE"] = str(phase_file)
    environment["CLAMAV_LARGEFILE_RESOURCE_PHASE_PROTOCOL"] = "pcre-start,post-pcre,complete"
    environment["CLAMAV_LARGEFILE_RESOURCE_PHASE_ACK_FILE"] = str(phase_ack_file)
    try:
        process = subprocess.Popen(
            args.command,
            env=environment,
            start_new_session=True,
            stdout=process_log_stream if process_log_stream is not None else None,
            stderr=subprocess.STDOUT if process_log_stream is not None else None,
        )
    except OSError as error:
        close_capture_streams()
        fail(f"acceptance command could not start: {error}")

    baseline_oom: dict[str, str | int] | None = None
    current: dict[str, int | str] = {
        "sample_count": 0,
        **{field: 0 for field in METRIC_FIELDS},
        "temporary_peak_bytes": 0,
        "oom_events_peak": 0,
        "oom_kill_events_peak": 0,
        "oom_cgroup_count": 0,
        "oom_cgroup_digest": "",
    }
    phase_peaks: dict[str, int | None] = {
        "pcre_rss_peak_kb": None,
        "post_pcre_rss_peak_kb": None,
    }
    last_error = "no successful process-tree sample"
    sampling_error: CaptureError | None = None
    sample_lock = threading.Lock()
    phase_measurements: Queue[
        tuple[str, dict[str, int], dict[str, str | int], int]
    ] = Queue()
    phase_watch_stop = threading.Event()
    phase_watch_errors: list[CaptureError] = []
    phase_watch_thread: threading.Thread | None = None
    next_regular_sample = 0.0
    try:
        while process.poll() is None:
            try:
                if baseline_oom is None:
                    baseline_oom = oom_sample(process.pid)
                if phase_watch_thread is None:
                    phase_watch_thread = threading.Thread(
                        target=watch_phase_events,
                        args=(
                            process, phase_file, temporary_root, baseline_oom,
                            phase_measurements, phase_ack_file,
                            phase_watch_stop, phase_watch_errors,
                        ),
                        name="largefile-phase-watch",
                        daemon=True,
                    )
                    phase_watch_thread.start()

                now = time.monotonic()
                if now >= next_regular_sample:
                    with sample_lock:
                        sample_row(
                            process.pid, temporary_root, phase_file,
                            baseline_oom, current, phase_peaks, sample_trace_stream,
                        )
                        current["sample_count"] = int(current["sample_count"]) + 1
                    drain_phase_measurements(
                        phase_measurements, baseline_oom, current, phase_peaks,
                        sample_trace_stream, sample_lock,
                    )
                    next_regular_sample = now + args.sample_interval_ms / 1000
            except CaptureError as error:
                last_error = str(error)
                # A single successful sample is not enough to claim a peak:
                # if a required sampler fails while the command is still
                # alive, the capture must fail closed instead of publishing
                # an incomplete resource trace. A failure racing process exit
                # is tolerated here and is handled by the no-sample check
                # below.
                if process.poll() is None:
                    sampling_error = error
                    terminate_child(process)
                    break
            if process.poll() is None:
                delay = max(0.001, min(
                    0.005, next_regular_sample - time.monotonic()
                ))
                time.sleep(delay)
    except KeyboardInterrupt:
        terminate_child(process)
        phase_watch_stop.set()
        if phase_watch_thread is not None:
            phase_watch_thread.join(timeout=5)
        cleanup_phase_ack()
        close_capture_streams()
        raise

    if phase_watch_thread is not None:
        # Let the watcher drain events it observed while the final regular
        # procfs sample was in flight.  Setting stop first would discard a
        # valid boundary merely because the wrapped command exited during
        # that slower sample.
        phase_watch_thread.join(timeout=5)
    phase_watch_stop.set()
    if phase_watch_thread is not None:
        phase_watch_thread.join(timeout=1)
        if phase_watch_thread.is_alive():
            phase_watch_errors.append(
                CaptureError("phase event sampler did not stop after command exit")
            )
    if baseline_oom is not None:
        drain_phase_measurements(
            phase_measurements, baseline_oom, current, phase_peaks,
            sample_trace_stream, sample_lock,
        )
    cleanup_phase_ack()
    if phase_watch_errors and sampling_error is None:
        sampling_error = phase_watch_errors[0]

    if sampling_error is not None:
        process.wait()
        close_capture_streams()
        fail(f"resource sampling failed while command was alive: {sampling_error}")
    if int(current["sample_count"]) < 1:
        close_capture_streams()
        fail(last_error)
    return_code = process.wait()
    close_capture_streams()
    append_phase_event(phase_file, "complete")
    if args.kind == "matcher" and args.id == "pcre":
        if phase_peaks["pcre_rss_peak_kb"] is None or phase_peaks["post_pcre_rss_peak_kb"] is None:
            fail("PCRE resource capture lacks both pcre and post-pcre phase samples")
    row: dict[str, int | str] = {
        "kind": args.kind,
        "id": args.id,
        "case_id": args.case_id,
        "source_manifest_sha256": resources.sha256(source),
        "build_identity_sha256": resources.sha256(build),
        "config_sha256": resources.sha256(config),
        "platform": f"{os.uname().sysname}-{os.uname().machine}",
        "sample_source": "procfs-process-tree",
        **current,
        "pcre_rss_peak_kb": (
            phase_peaks["pcre_rss_peak_kb"]
            if phase_peaks["pcre_rss_peak_kb"] is not None else "-"
        ),
        "post_pcre_rss_peak_kb": (
            phase_peaks["post_pcre_rss_peak_kb"]
            if phase_peaks["post_pcre_rss_peak_kb"] is not None else "-"
        ),
    }
    resources.validate_resource_rows([{
        field: str(row[field]) for field in resources.RESOURCE_HEADER
    }], {
        (args.kind, args.id, args.case_id): {
            field: str(row[field]) for field in resources.RESOURCE_HEADER
        },
    })
    append_row(output, row, root)
    print(
        f"captured acceptance resources for {args.kind}:{args.id}:{args.case_id} "
        f"({current['sample_count']} samples; command exit {return_code})"
    )
    return return_code if return_code >= 0 else 128 + (-return_code)


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if "--" not in raw_argv:
        command_argv: list[str] = []
        option_argv = raw_argv
    else:
        separator = raw_argv.index("--")
        option_argv = raw_argv[:separator]
        command_argv = raw_argv[separator + 1:]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_root", type=Path)
    parser.add_argument("--kind", required=True)
    parser.add_argument("--id", required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--build-identity", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--temporary-root", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path(resources.RESOURCE_PATH))
    parser.add_argument("--phase-file", type=Path)
    parser.add_argument("--process-log", type=Path)
    parser.add_argument("--sample-log", type=Path)
    parser.add_argument("--sample-interval-ms", type=int, default=100)
    args = parser.parse_args(option_argv)
    if args.sample_interval_ms < 10 or args.sample_interval_ms > 10000:
        parser.error("--sample-interval-ms must be between 10 and 10000")
    args.command = command_argv
    if not args.command:
        parser.error("an acceptance command is required after --")
    try:
        return capture(args)
    except (CaptureError, ValueError, OSError, csv.Error) as error:
        print(f"large-file acceptance resource capture failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
