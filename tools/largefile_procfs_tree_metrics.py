#!/usr/bin/env python3
"""Return one fail-closed Linux /proc process-tree resource sample.

The output is a single tab-separated row containing aggregate metrics for the
given process roots and all of their descendants:

  rss_kb, pss_kb, vas_kb, swap_kb, minor_faults, major_faults,
  read_bytes, write_bytes, cancelled_write_bytes, process_count, pid_list

The counters are read from the selected processes themselves, not from a
single client process.  This is intended for qualification evidence; a
missing selected-process metric is an error rather than a silently incomplete
sample.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


PROC = Path("/proc")
PID_RE = re.compile(r"^[0-9]+$")


def fail(message: str, status: int = 3) -> "NoReturn":
    print(message, file=sys.stderr)
    raise SystemExit(status)


def numeric_status(status_path: Path, pid: int) -> dict[str, int]:
    try:
        fields: dict[str, int] = {}
        for raw in status_path.read_text(encoding="utf-8").splitlines():
            key, separator, value = raw.partition(":")
            if not separator:
                continue
            value = value.strip().split(None, 1)[0] if value.strip() else ""
            if key in {"Pid", "PPid", "VmRSS", "VmSize", "VmSwap"}:
                if not value.isdigit():
                    raise ValueError(f"{key} is not numeric")
                fields[key] = int(value)
        required = {"Pid", "PPid", "VmRSS", "VmSize", "VmSwap"}
        if set(fields) != required or fields["Pid"] != pid:
            raise ValueError("status fields are incomplete")
        return fields
    except (OSError, UnicodeError, ValueError):
        raise FileNotFoundError(status_path)


def pss_kb(pid_path: Path) -> int:
    fields = {}
    try:
        for raw in (pid_path / "smaps_rollup").read_text(encoding="utf-8").splitlines():
            key, separator, value = raw.partition(":")
            if separator and key == "Pss":
                value = value.strip().split(None, 1)[0]
                if not value.isdigit():
                    raise ValueError("Pss is not numeric")
                fields[key] = int(value)
                break
    except (OSError, UnicodeError, ValueError):
        raise FileNotFoundError(pid_path / "smaps_rollup")
    if "Pss" not in fields:
        raise FileNotFoundError(pid_path / "smaps_rollup")
    return fields["Pss"]


def stat_faults(pid_path: Path) -> tuple[int, int]:
    try:
        raw = (pid_path / "stat").read_text(encoding="utf-8")
        closing = raw.rfind(")")
        if closing < 0:
            raise ValueError("stat command name is incomplete")
        after_name = raw[closing + 1 :].split()
        # After the command name, index 0 is field 3 (state); fields 10 and
        # 12 are therefore indexes 7 and 9 in this suffix.
        if len(after_name) <= 9:
            raise ValueError("stat fault fields are incomplete")
        minor = after_name[7]
        major = after_name[9]
        if not minor.isdigit() or not major.isdigit():
            raise ValueError("stat fault fields are not numeric")
        return int(minor), int(major)
    except (OSError, UnicodeError, ValueError):
        raise FileNotFoundError(pid_path / "stat")


def io_counters(pid_path: Path) -> tuple[int, int, int]:
    wanted = {"read_bytes", "write_bytes", "cancelled_write_bytes"}
    values: dict[str, int] = {}
    try:
        for raw in (pid_path / "io").read_text(encoding="utf-8").splitlines():
            key, separator, value = raw.partition(":")
            if separator and key in wanted:
                value = value.strip()
                if not value.isdigit():
                    raise ValueError(f"{key} is not numeric")
                values[key] = int(value)
    except (OSError, UnicodeError, ValueError):
        raise FileNotFoundError(pid_path / "io")
    if values.keys() != wanted:
        raise FileNotFoundError(pid_path / "io")
    return values["read_bytes"], values["write_bytes"], values["cancelled_write_bytes"]


def collect_processes() -> tuple[dict[int, int], dict[int, dict[str, int]]]:
    if os.name != "posix" or not PROC.is_dir():
        fail("Linux procfs is unavailable")
    parents: dict[int, int] = {}
    processes: dict[int, dict[str, int]] = {}
    try:
        entries = list(PROC.iterdir())
    except OSError as error:
        fail(f"cannot enumerate procfs: {error}")
    for entry in entries:
        if not PID_RE.fullmatch(entry.name):
            continue
        pid = int(entry.name)
        try:
            status = numeric_status(entry / "status", pid)
        except FileNotFoundError:
            # A process can disappear between /proc enumeration and a read.
            # It is safe to omit it unless it is one of the requested roots;
            # selected roots are checked explicitly below.
            continue
        parents[pid] = status["PPid"]
        try:
            pss = pss_kb(entry)
            minor, major = stat_faults(entry)
            read_bytes, write_bytes, cancelled = io_counters(entry)
        except FileNotFoundError:
            # Keep the topology even when a metric read races process exit or
            # is denied.  Selection below will fail closed instead of silently
            # dropping a descendant from the aggregate.
            continue
        processes[pid] = {
            "ppid": status["PPid"],
            "rss_kb": status["VmRSS"],
            "pss_kb": pss,
            "vas_kb": status["VmSize"],
            "swap_kb": status["VmSwap"],
            "minor_faults": minor,
            "major_faults": major,
            "read_bytes": read_bytes,
            "write_bytes": write_bytes,
            "cancelled_write_bytes": cancelled,
        }
    return parents, processes


def main(argv: list[str]) -> int:
    if not argv:
        print(f"usage: {Path(sys.argv[0]).name} ROOT_PID...", file=sys.stderr)
        return 2
    roots: list[int] = []
    for raw in argv:
        if not PID_RE.fullmatch(raw) or int(raw) < 1:
            print(f"invalid process root PID: {raw}", file=sys.stderr)
            return 2
        value = int(raw)
        if value not in roots:
            roots.append(value)

    parents, processes = collect_processes()
    missing_roots = [str(pid) for pid in roots if pid not in parents]
    if missing_roots:
        fail("requested process root disappeared from procfs: " + ",".join(missing_roots))

    selected = set(roots)
    changed = True
    while changed:
        changed = False
        for pid, ppid in parents.items():
            if pid not in selected and ppid in selected:
                selected.add(pid)
                changed = True

    if not selected:
        fail("process tree is empty")
    missing_metrics = sorted(pid for pid in selected if pid not in processes)
    if missing_metrics:
        fail(
            "selected process lacks required procfs metrics: "
            + ",".join(str(pid) for pid in missing_metrics)
        )
    rows = [processes[pid] for pid in sorted(selected)]
    names = (
        "rss_kb",
        "pss_kb",
        "vas_kb",
        "swap_kb",
        "minor_faults",
        "major_faults",
        "read_bytes",
        "write_bytes",
        "cancelled_write_bytes",
    )
    totals = [sum(row[name] for row in rows) for name in names]
    print("\t".join(str(value) for value in totals + [len(rows), ",".join(str(pid) for pid in sorted(selected))]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
