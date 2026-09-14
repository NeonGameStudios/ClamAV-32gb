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
import subprocess
import sys
import time

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
PHASE_EVENTS = {"pcre-start", "post-pcre", "complete"}
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


def run_sampler(tool: Path, pid: int) -> list[str]:
    try:
        result = subprocess.run(
            [sys.executable, str(tool), str(pid)],
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
    fields = run_sampler(METRICS_TOOL, pid)
    if len(fields) != 11 or any(not value.isdigit() for value in fields[:10]):
        fail("process-tree resource sampler returned an invalid metric row")
    return dict(zip(
        (
            "rss_kb", "pss_kb", "vas_kb", "swap_kb", "minor_faults",
            "major_faults", "read_bytes", "write_bytes",
            "cancelled_write_bytes", "process_count",
        ),
        (int(value) for value in fields[:10]),
    ))


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


def phase_state(path: Path) -> str:
    state = "pre-pcre"
    if path.is_symlink():
        fail(f"phase protocol is symlinked: {path}")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise CaptureError(f"cannot read phase protocol {path}: {error}") from error
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
        else:
            state = "complete"
    return state


def sample_row(
    pid: int,
    temporary_root: Path,
    phase_file: Path,
    baseline_oom: dict[str, str | int],
    current: dict[str, int],
    phase_peaks: dict[str, int | None],
) -> dict[str, int | str]:
    metric = metric_sample(pid)
    oom = oom_sample(pid)
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
    current["temporary_peak_bytes"] = max(
        current["temporary_peak_bytes"], temporary_size(temporary_root)
    )

    state = phase_state(phase_file)
    phase_rss_key = {
        "pcre": "pcre_rss_peak_kb",
        "post-pcre": "post_pcre_rss_peak_kb",
    }.get(state)
    if phase_rss_key:
        phase_peaks[phase_rss_key] = max(
            int(phase_peaks[phase_rss_key] or 0), metric["rss_kb"]
        )
    return current


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

    environment = os.environ.copy()
    environment["CLAMAV_LARGEFILE_RESOURCE_PHASE_FILE"] = str(phase_file)
    environment["CLAMAV_LARGEFILE_RESOURCE_PHASE_PROTOCOL"] = "pcre-start,post-pcre,complete"
    try:
        process = subprocess.Popen(
            args.command,
            env=environment,
            start_new_session=True,
        )
    except OSError as error:
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
    try:
        while process.poll() is None:
            try:
                if baseline_oom is None:
                    baseline_oom = oom_sample(process.pid)
                sample_row(
                    process.pid, temporary_root, phase_file,
                    baseline_oom, current, phase_peaks,
                )
                current["sample_count"] = int(current["sample_count"]) + 1
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
                time.sleep(args.sample_interval_ms / 1000)
    except KeyboardInterrupt:
        terminate_child(process)
        raise

    if sampling_error is not None:
        process.wait()
        fail(f"resource sampling failed while command was alive: {sampling_error}")
    if int(current["sample_count"]) < 1:
        fail(last_error)
    return_code = process.wait()
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
