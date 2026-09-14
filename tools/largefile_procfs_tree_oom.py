#!/usr/bin/env python3
"""Read fail-closed cgroup-v2 OOM counters for process roots.

The output is ``oom_events<TAB>oom_kill_events<TAB>cgroup_count<TAB>cgroup_digest``.  Cgroup-v2
``memory.events`` includes descendants, so one counter row per distinct
cgroup containing a requested root is sufficient for the service gate.  The
gate compares a baseline with later samples; it never treats a missing or
unsupported OOM source as a clean result.
"""

from __future__ import annotations

import os
import hashlib
import re
import sys
from pathlib import Path


PID_RE = re.compile(r"^[0-9]+$")


def fail(message: str, status: int = 3) -> "NoReturn":
    print(message, file=sys.stderr)
    raise SystemExit(status)


def cgroup2_mounts() -> list[Path]:
    mounts: list[Path] = []
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return mounts
    for line in lines:
        before, separator, after = line.partition(" - ")
        if not separator:
            continue
        pre = before.split()
        post = after.split()
        if len(pre) >= 5 and post and post[0] == "cgroup2":
            mount = Path(pre[4].replace("\\040", " ").replace("\\011", "\t"))
            if mount not in mounts:
                mounts.append(mount)
    return mounts


def root_cgroup_path(pid: int) -> str:
    try:
        lines = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        raise FileNotFoundError(f"/proc/{pid}/cgroup")
    for line in lines:
        hierarchy, separator, path = line.partition(":")
        if not separator:
            continue
        controllers, separator, path = path.partition(":")
        if separator and hierarchy == "0" and controllers == "":
            if path.startswith("/"):
                return path
            break
    raise RuntimeError(f"process {pid} has no cgroup-v2 membership")


def memory_events_path(cgroup_path: str) -> Path:
    relative = cgroup_path.lstrip("/")
    for mount in cgroup2_mounts():
        candidate = mount / relative / "memory.events"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"memory.events for cgroup {cgroup_path}")


def read_events(path: Path) -> tuple[int, int]:
    values: dict[str, int] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            key, separator, raw = line.partition(" ")
            if separator and key in {"oom", "oom_kill"} and raw.isdigit():
                values[key] = int(raw)
    except (OSError, UnicodeError):
        raise FileNotFoundError(path)
    if set(values) != {"oom", "oom_kill"}:
        raise RuntimeError(f"memory.events lacks required OOM counters: {path}")
    return values["oom"], values["oom_kill"]


def main(argv: list[str]) -> int:
    if not argv:
        print(f"usage: {Path(sys.argv[0]).name} ROOT_PID...", file=sys.stderr)
        return 2
    if os.name != "posix" or not Path("/proc").is_dir():
        fail("Linux procfs is unavailable")
    roots: list[int] = []
    for raw in argv:
        if not PID_RE.fullmatch(raw) or int(raw) < 1:
            print(f"invalid process root PID: {raw}", file=sys.stderr)
            return 2
        pid = int(raw)
        if pid not in roots:
            roots.append(pid)

    paths: set[str] = set()
    for pid in roots:
        try:
            paths.add(root_cgroup_path(pid))
        except FileNotFoundError:
            fail(f"requested process root disappeared from procfs: {pid}")
        except RuntimeError as error:
            fail(str(error))
    if not paths:
        fail("no cgroup-v2 process roots were selected")

    total_oom = 0
    total_oom_kill = 0
    for path in sorted(paths):
        try:
            oom, oom_kill = read_events(memory_events_path(path))
        except (FileNotFoundError, RuntimeError) as error:
            fail(str(error))
        total_oom += oom
        total_oom_kill += oom_kill
    digest = hashlib.sha256("\n".join(sorted(paths)).encode("utf-8")).hexdigest()
    print(f"{total_oom}\t{total_oom_kill}\t{len(paths)}\t{digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
