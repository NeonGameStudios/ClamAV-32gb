#!/usr/bin/env python3
"""Regression tests for the cgroup-v2 OOM counter sampler."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SAMPLER = ROOT / "tools" / "largefile_procfs_tree_oom.py"


def main() -> int:
    if sys.platform != "linux":
        print("large-file procfs OOM test skipped: Linux procfs is unavailable")
        return 0
    result = subprocess.run(
        [sys.executable, str(SAMPLER), str(os.getpid())],
        check=True,
        text=True,
        capture_output=True,
    )
    fields = result.stdout.rstrip("\n").split("\t")
    if len(fields) != 4 or any(not value.isdigit() for value in fields[:3]) or len(fields[3]) != 64:
        raise AssertionError(f"malformed OOM sampler output: {result.stdout!r}")
    if int(fields[2]) < 1:
        raise AssertionError("OOM sampler did not identify a cgroup")
    duplicate = subprocess.run(
        [sys.executable, str(SAMPLER), str(os.getpid()), str(os.getpid())],
        check=True,
        text=True,
        capture_output=True,
    )
    if duplicate.stdout != result.stdout:
        raise AssertionError("OOM sampler double-counted a duplicate cgroup root")
    rejected = subprocess.run(
        [sys.executable, str(SAMPLER), "invalid"],
        text=True,
        capture_output=True,
    )
    if rejected.returncode == 0:
        raise AssertionError("OOM sampler accepted a non-numeric PID")
    print("large-file procfs OOM test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
