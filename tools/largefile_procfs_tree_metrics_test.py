#!/usr/bin/env python3
"""Regression tests for the Linux process-tree metrics sampler."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SAMPLER = ROOT / "tools" / "largefile_procfs_tree_metrics.py"


def main() -> int:
    if sys.platform != "linux":
        print("large-file procfs tree metrics test skipped: Linux procfs is unavailable")
        return 0

    child_file = Path(os.environ.get("TMPDIR", "/tmp")) / f"clamav-metrics-child-{os.getpid()}"
    child_file.unlink(missing_ok=True)
    parent = subprocess.Popen(
        ["sh", "-c", "sleep 10 & printf '%s\\n' \"$!\" > \"$1\"; wait", "sh", str(child_file)]
    )
    child = None
    try:
        for _ in range(100):
            if child_file.exists() and child_file.read_text().strip():
                child = int(child_file.read_text().strip())
                break
            time.sleep(0.01)
        if child is None:
            raise AssertionError("child process did not start")

        result = subprocess.run(
            [sys.executable, str(SAMPLER), str(parent.pid)],
            check=True,
            text=True,
            capture_output=True,
        )
        fields = result.stdout.rstrip("\n").split("\t")
        if len(fields) != 11 or any(not field for field in fields):
            raise AssertionError(f"malformed sampler output: {result.stdout!r}")
        numeric = [int(value) for value in fields[:10]]
        if any(value < 0 for value in numeric) or numeric[0] == 0 or numeric[9] < 2:
            raise AssertionError(f"invalid process metrics: {fields!r}")
        pids = {int(value) for value in fields[10].split(",")}
        if pids != set(map(int, fields[10].split(","))) or parent.pid not in pids or child not in pids:
            raise AssertionError(f"sampler omitted a process: {fields!r}")

        duplicate = subprocess.run(
            [sys.executable, str(SAMPLER), str(parent.pid), str(child)],
            check=True,
            text=True,
            capture_output=True,
        )
        duplicate_fields = duplicate.stdout.rstrip("\n").split("\t")
        if len(duplicate_fields) != 11 or duplicate_fields[9:] != fields[9:]:
            raise AssertionError("sampler double-counted a descendant root")

        rejected = subprocess.run(
            [sys.executable, str(SAMPLER), "invalid"],
            text=True,
            capture_output=True,
        )
        if rejected.returncode == 0:
            raise AssertionError("sampler accepted a non-numeric PID")
        print("large-file procfs tree metrics test passed")
        return 0
    finally:
        parent.terminate()
        try:
            parent.wait(timeout=2)
        except subprocess.TimeoutExpired:
            parent.kill()
            parent.wait()
        child_file.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
