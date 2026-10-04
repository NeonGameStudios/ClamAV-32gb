#!/usr/bin/env python3
"""Capture a direct scanner input around one command without copying the input.

This is an evidence primitive, not an R04 acceptance-case producer. The
caller must separately retain the scanner report/log, resource measurements,
independent oracle, and source/build/config/database provenance. A failed or
interrupted command never turns into a passing qualification record.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


EDGE_SIZE = 32 * 1024 * 1024 * 1024
STABLE_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_blocks")


def input_identity(path: Path) -> dict[str, int | str | None]:
    """Read and hash the actual, stable regular file with no final symlink."""
    if not path.is_absolute() or ".." in path.parts or path.is_symlink():
        raise ValueError(f"input must be an absolute, non-symlinked file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"input is not a regular file: {path}")
        allocated = before.st_blocks * 512
        try:
            first_hole = os.lseek(stream.fileno(), 0, os.SEEK_HOLE)
        except OSError as error:
            if before.st_size >= EDGE_SIZE:
                raise ValueError("exact-edge input lacks a verifiable hole layout") from error
            first_hole = None
        if before.st_size >= EDGE_SIZE and (allocated < before.st_size or
                                            first_hole != before.st_size):
            raise ValueError("exact-edge input is not fully materialized")
        stream.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        path_after = os.stat(path, follow_symlinks=False)
    if any(getattr(before, field) != getattr(after, field) or
           getattr(before, field) != getattr(path_after, field)
           for field in STABLE_FIELDS):
        raise ValueError("input changed while it was being hashed")
    return {
        "input": str(path), "size": before.st_size,
        "sha256": digest.hexdigest(), "allocated_bytes": allocated,
        "first_hole": first_hole,
        "device": before.st_dev, "inode": before.st_ino,
        "mtime_ns": before.st_mtime_ns, "ctime_ns": before.st_ctime_ns,
    }


def exclusive_bytes(path: Path, data: bytes) -> None:
    """Publish and sync one immutable-at-creation evidence sidecar."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def exclusive_json(path: Path, payload: dict) -> bytes:
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    exclusive_bytes(path, data)
    return data


def oracle_snapshot(source: Path, destination: Path, identity: dict, role: str) -> str:
    if source.is_symlink() or not source.is_file() or source.resolve() == destination.resolve():
        raise ValueError("independent oracle is missing, symlinked, or already the evidence target")
    before = source.stat()
    data = source.read_bytes()
    after = source.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > 64 * 1024 or \
            any(getattr(before, field) != getattr(after, field) for field in STABLE_FIELDS):
        raise ValueError("independent oracle changed or exceeds 64 KiB")

    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"independent oracle repeats {key}")
            result[key] = value
        return result

    try:
        oracle = json.loads(data, object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("independent oracle is not valid JSON") from error
    if not isinstance(oracle, dict) or type(oracle.get("version")) is not int or \
            oracle["version"] != 1 or oracle.get("fixture_role") != role or \
            oracle.get("input") != identity["input"] or \
            type(oracle.get("size")) is not int or oracle["size"] != identity["size"] or \
            oracle.get("sha256") != identity["sha256"] or \
            oracle.get("case_id") not in {
                "clamscan:file:clean-edge", "clamscan:file:detection-edge",
                "clamscan:file:limit-edge",
            }:
        raise ValueError("independent oracle does not bind the pre-scan input/case")
    suffix = oracle["case_id"].rsplit(":", 1)[-1]
    expected = {
        "clean-edge": ("COMPLETE", 0),
        "detection-edge": ("DETECTION_TERMINATED", 1),
        "limit-edge": ("LIMIT_INCOMPLETE", 2),
    }[suffix]
    signature, offset = oracle.get("alert_signature"), oracle.get("alert_offset")
    offset_scope = oracle.get("alert_offset_scope")
    detection = suffix == "detection-edge"
    valid_alert = (
        isinstance(signature, str) and signature not in ("", "-") and
        type(offset) is int and offset >= 0 and
        offset_scope in {"root-input", "nested-member"}
    ) if detection else signature == "-" and offset is None and offset_scope == "none"
    if oracle.get("completion") != expected[0] or \
            type(oracle.get("exit_code")) is not int or oracle["exit_code"] != expected[1] or \
            not valid_alert or not isinstance(oracle.get("reason"), str) or \
            not oracle["reason"] or "\t" in oracle["reason"] or "\n" in oracle["reason"]:
        raise ValueError("independent oracle has an invalid outcome contract")
    if suffix == "limit-edge" and oracle["reason"] != "Heuristics.Limits.Exceeded.MaxFileSize":
        raise ValueError("independent oracle has the wrong limit reason")
    for field, name in (
        ("source_manifest_sha256", "source-content.sha256"),
        ("build_identity_sha256", "clamscan"),
        ("config_sha256", "CMakeCache.txt"),
        ("database_sha256", "database.ndb"),
    ):
        artifact = destination.parent / name
        if not artifact.is_file() or artifact.is_symlink() or \
                not isinstance(oracle.get(field), str) or \
                not re.fullmatch(r"[0-9a-f]{64}", oracle[field]):
            raise ValueError(f"independent oracle lacks staged {field}")
        digest = hashlib.sha256()
        with artifact.open("rb") as stream:
            for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != oracle[field]:
            raise ValueError(f"independent oracle does not match staged {field}")
    exclusive_bytes(destination, data)
    return hashlib.sha256(data).hexdigest()


def capture(root: Path, role: str, input_path: Path, command: list[str],
            oracle_source: Path | None = None) -> int:
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"evidence root must be an existing directory: {root}")
    if not role or any(character in role for character in "/\\,\t\n"):
        raise ValueError("fixture role is invalid")
    if not command or not command[0]:
        raise ValueError("a scanner/resource-wrapper command is required")
    provenance = root / "provenance"
    if provenance.is_symlink():
        raise ValueError("provenance directory must not be a symlink")
    if provenance.exists() and not provenance.is_dir():
        raise ValueError("provenance path is not a directory")
    before_path = provenance / "direct-inputs-before.json"
    after_path = provenance / "direct-inputs-after.json"
    oracle_path = provenance / "direct-oracle.json"
    result_path = provenance / "direct-command-result.json"
    if before_path.exists() or before_path.is_symlink() or \
            after_path.exists() or after_path.is_symlink() or \
            oracle_path.exists() or oracle_path.is_symlink() or \
            result_path.exists() or result_path.is_symlink():
        raise ValueError("direct input sidecars already exist; refusing overwrite")
    identity = input_identity(input_path)
    oracle_hash = None
    if oracle_source is not None:
        oracle_hash = oracle_snapshot(oracle_source, oracle_path, identity, role)
    before = exclusive_json(before_path, {
        "version": 1, "inputs": {role: identity},
    })
    try:
        result = subprocess.run(command, check=False)
        exit_code = result.returncode
    except OSError as error:
        # Preserve the before sidecar and still attempt the after measurement.
        exit_code = 125
        print(f"scanner command could not start: {error}", file=sys.stderr)
    after = exclusive_json(after_path, {
        "version": 1, "inputs": {role: input_identity(input_path)},
    })
    exclusive_json(result_path, {
        "version": 1, "command": command, "exit_code": exit_code,
        "input_stable": before == after, "oracle_sha256": oracle_hash,
    })
    if before != after:
        raise ValueError("direct input identity changed during the scanner command")
    if exit_code < 0:
        return 128 - exit_code
    return exit_code


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if "--" not in raw:
        raise ValueError("a command is required after --")
    separator = raw.index("--")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_root", type=Path)
    parser.add_argument("--fixture-role", required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--oracle", required=True, type=Path,
                        help="precomputed independent JSON oracle; copied before scan")
    args = parser.parse_args(raw[:separator])
    return capture(args.evidence_root, args.fixture_role, args.input,
                   raw[separator + 1:], args.oracle)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as error:
        print(f"direct input capture failed: {error}", file=sys.stderr)
        raise SystemExit(125) from error
