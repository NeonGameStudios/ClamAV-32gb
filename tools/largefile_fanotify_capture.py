#!/usr/bin/env python3
"""Capture real Linux fanotify permission events for one on-access case.

This is a capture primitive for R13, not a qualification shortcut.  It must
run as root on Linux against an already-mounted private test filesystem.  The
recorder creates its own permission-event group, records the kernel metadata,
and replies FAN_ALLOW so that the clamonacc group remains the authority for
the observed open.  It never invents a kernel event or a scan result.

The caller supplies the current fixture digest and the actor UID.  A separate
clamd/clamonacc process supervisor is intentionally left outside this small
primitive: the scan report and process log are retained by that supervisor and
are bound by tools/largefile_fanotify_evidence.py.  The emitted
``observer_response`` is this recorder's own FAN_ALLOW reply, not ClamAV's
permission decision; a derived R13 kernel artifact must retain the latter as
``permission_response``.
"""

from __future__ import annotations

import argparse
import binascii
import ctypes
from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import platform
import pwd
import re
import select
import struct
import subprocess
import sys
import time

FAN_CLASS_CONTENT = 0x00000004
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_UNLIMITED_QUEUE = 0x00000010
FAN_UNLIMITED_MARKS = 0x00000020
FAN_MARK_ADD = 0x00000001
FAN_EVENT_ON_CHILD = 0x08000000
FAN_OPEN_PERM = 0x00010000
FAN_ALLOW = 0x01
AT_FDCWD = -100
EVENT_HEADER = struct.Struct("<IBBH Qii")
RESPONSE = struct.Struct("<iI")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")


class CaptureError(RuntimeError):
    """A fail-visible capture error."""


@dataclass(frozen=True)
class MountInfo:
    path: str
    filesystem: str
    private: bool


def fail(message: str) -> None:
    raise CaptureError(message)


def require_digest(value: str) -> str:
    if not isinstance(value, str) or HASH_RE.fullmatch(value) is None:
        fail("fixture SHA-256 must be 64 lowercase hexadecimal characters")
    return value


def _unescape_mountinfo(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value
    )


def parse_mountinfo(text: str, mount_path: Path) -> MountInfo:
    """Return the exact mount entry and conservative private-propagation bit."""
    wanted = str(mount_path)
    for line in text.splitlines():
        if " - " not in line:
            continue
        left, right = line.split(" - ", 1)
        fields = left.split()
        post = right.split()
        if len(fields) < 6 or not post:
            continue
        if _unescape_mountinfo(fields[4]) != wanted:
            continue
        optional = fields[6:]
        private = not any(
            item.startswith("shared:") or item.startswith("master:")
            for item in optional
        )
        return MountInfo(wanted, post[0], private)
    fail(f"mount path is not present in /proc/self/mountinfo: {wanted}")


def require_private_mount(path: Path) -> MountInfo:
    if platform.system() != "Linux":
        fail("fanotify permission capture requires Linux")
    if os.geteuid() != 0:
        fail("fanotify permission capture requires effective UID 0")
    if path.is_symlink() or not path.is_dir():
        fail(f"mount path is missing, symlinked, or not a directory: {path}")
    resolved = path.resolve()
    if not os.path.ismount(resolved):
        fail(f"path is not a mount point: {resolved}")
    info = parse_mountinfo(Path("/proc/self/mountinfo").read_text(), resolved)
    if not info.private:
        fail(f"mount is not privately propagated: {resolved}")
    return info


def parse_event_batch(data: bytes) -> list[dict[str, int | str]]:
    """Parse only complete fanotify metadata records from one read."""
    events: list[dict[str, int | str]] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < EVENT_HEADER.size:
            fail("fanotify returned a truncated metadata header")
        event_len, version, _reserved, metadata_len, mask, fd, pid = (
            EVENT_HEADER.unpack_from(data, offset)
        )
        if event_len < EVENT_HEADER.size or event_len < metadata_len:
            fail("fanotify returned an invalid event length")
        if offset + event_len > len(data):
            fail("fanotify returned a truncated event")
        if metadata_len < EVENT_HEADER.size:
            fail("fanotify returned an invalid metadata length")
        events.append({
            "event_len": event_len,
            "metadata_version": version,
            "metadata_len": metadata_len,
            "mask": mask,
            "fd": fd,
            "pid": pid,
            "raw_metadata_hex": binascii.hexlify(
                data[offset:offset + metadata_len]
            ).decode("ascii"),
        })
        offset += event_len
    return events


def mask_names(mask: int) -> list[str]:
    names = []
    if mask & FAN_OPEN_PERM:
        names.append("FAN_OPEN_PERM")
    if mask & FAN_EVENT_ON_CHILD:
        names.append("FAN_EVENT_ON_CHILD")
    if not names:
        names.append(f"0x{mask:x}")
    return names


def _write_response(fanotify_fd: int, event_fd: int) -> None:
    payload = RESPONSE.pack(event_fd, FAN_ALLOW)
    sent = 0
    while sent < len(payload):
        try:
            count = os.write(fanotify_fd, payload[sent:])
        except InterruptedError:
            continue
        if count <= 0:
            fail("fanotify permission response write made no progress")
        sent += count


def _close_event_fd(fd: int) -> None:
    if fd < 0:
        return
    try:
        os.close(fd)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise


def _fanotify_init() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.fanotify_init
    function.argtypes = [ctypes.c_uint, ctypes.c_uint]
    function.restype = ctypes.c_int
    flags = (
        FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK |
        FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS
    )
    event_flags = os.O_RDONLY | getattr(os, "O_LARGEFILE", 0) | os.O_CLOEXEC
    fd = function(flags, event_flags)
    if fd < 0:
        error = ctypes.get_errno()
        fail(f"fanotify_init failed: {os.strerror(error)}")
    return fd


def _fanotify_mark(fd: int, mount_path: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.fanotify_mark
    function.argtypes = [
        ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int,
        ctypes.c_char_p,
    ]
    function.restype = ctypes.c_int
    result = function(
        # ClamAV's OnAccessIncludePath path uses FAN_MARK_ADD rather than
        # FAN_MARK_MOUNT.  Keep the recorder on that same supported path;
        # the caller separately proves that the containing test filesystem is
        # a private mount.
        fd, FAN_MARK_ADD, FAN_EVENT_ON_CHILD | FAN_OPEN_PERM, AT_FDCWD,
        os.fsencode(str(mount_path)),
    )
    if result < 0:
        error = ctypes.get_errno()
        fail(f"fanotify_mark failed: {os.strerror(error)}")


def _actor_preexec(uid: int, gid: int) -> None:
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)


def start_actor(fixture: Path, uid: int) -> subprocess.Popen[str]:
    if uid <= 0 or uid > 65535:
        fail("actor UID must be a non-root value between 1 and 65535")
    try:
        account = pwd.getpwuid(uid)
    except KeyError as error:
        raise CaptureError(f"actor UID is not present in /etc/passwd: {uid}") from error
    code = (
        "import json, os, sys\n"
        "try:\n"
        "    with open(sys.argv[1], 'rb') as stream:\n"
        "        stream.read(1)\n"
        "except OSError as error:\n"
        "    print(json.dumps({'opened': False, 'errno': error.errno}), flush=True)\n"
        "    raise SystemExit(1)\n"
        "else:\n"
        "    print(json.dumps({'opened': True}), flush=True)\n"
    )
    return subprocess.Popen(
        [sys.executable, "-c", code, str(fixture)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        close_fds=True,
        start_new_session=True,
        preexec_fn=lambda: _actor_preexec(uid, account.pw_gid),
    )


def capture(
    mount_path: Path,
    fixture: Path,
    kernel_artifact: Path,
    actor_artifact: Path,
    fixture_sha256: str,
    actor_uid: int,
    timeout_seconds: float,
    case_name: str,
) -> dict[str, object]:
    mount = require_private_mount(mount_path.resolve())
    if fixture.is_symlink() or not fixture.is_file():
        fail(f"fixture is missing, symlinked, or not a regular file: {fixture}")
    fixture = fixture.resolve()
    try:
        fixture.relative_to(Path(mount.path))
    except ValueError as error:
        raise CaptureError("fixture is outside the requested private mount") from error
    fixture_sha256 = require_digest(fixture_sha256)
    if timeout_seconds <= 0 or timeout_seconds > 3600:
        fail("capture timeout must be greater than zero and no more than 3600 seconds")
    if case_name not in {"clean", "detection", "limit", "resource", "timeout", "parser"}:
        fail(f"unknown R13 case name: {case_name}")

    fanotify_fd = _fanotify_init()
    actor: subprocess.Popen[str] | None = None
    events: list[dict[str, object]] = []
    sequence = 0
    target_event_ids: list[int] = []
    try:
        _fanotify_mark(fanotify_fd, Path(mount.path))
        actor = start_actor(fixture, actor_uid)
        poller = select.poll()
        poller.register(fanotify_fd, select.POLLIN)
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            for _fd, _mask in poller.poll(100):
                try:
                    raw = os.read(fanotify_fd, 1024 * 1024)
                except BlockingIOError:
                    continue
                if not raw:
                    continue
                for event in parse_event_batch(raw):
                    sequence += 1
                    event_fd = int(event["fd"])
                    try:
                        event_path = os.readlink(f"/proc/self/fd/{event_fd}")
                    except OSError as error:
                        event_path = f"<unresolved:{error.errno}>"
                    is_target = os.path.realpath(event_path) == str(fixture)
                    record = {
                        "event_id": sequence,
                        "event_kind": "FAN_OPEN_PERM",
                        "target": is_target,
                        "fixture_sha256": fixture_sha256,
                        "path": event_path,
                        "timestamp_ns": time.time_ns(),
                        "collector_pid": os.getpid(),
                        "event_fd": event_fd,
                        "event_pid": int(event["pid"]),
                        "event_len": int(event["event_len"]),
                        "metadata_len": int(event["metadata_len"]),
                        "mask": int(event["mask"]),
                        "mask_names": mask_names(int(event["mask"])),
                        "metadata_version": int(event["metadata_version"]),
                        "raw_metadata_hex": event["raw_metadata_hex"],
                        "observer_response": "FAN_ALLOW",
                    }
                    events.append(record)
                    if is_target:
                        target_event_ids.append(sequence)
                    if event_fd >= 0:
                        _write_response(fanotify_fd, event_fd)
                        _close_event_fd(event_fd)
            if actor.poll() is not None:
                break
        if actor.poll() is None:
            actor.kill()
            actor.wait(timeout=5)
            fail("unprivileged actor exceeded the capture timeout")
        stdout, stderr = actor.communicate(timeout=5)
        if not target_event_ids:
            fail("no FAN_OPEN_PERM event for the requested fixture was observed")
        try:
            actor_result = json.loads(stdout.strip())
        except json.JSONDecodeError as error:
            raise CaptureError("actor did not emit a JSON result") from error
        if not isinstance(actor_result, dict) or type(actor_result.get("opened")) is not bool:
            fail("actor result has an invalid opened field")
        actor_result.update({
            "case_name": case_name,
            "fixture": str(fixture),
            "fixture_sha256": fixture_sha256,
            "actor_uid": actor_uid,
            "actor_exit_code": actor.returncode,
            "stderr": stderr,
            "event_id": target_event_ids[0],
            "observed_action": "allow" if actor_result["opened"] else "deny",
        })
        kernel_artifact.parent.mkdir(parents=True, exist_ok=True)
        actor_artifact.parent.mkdir(parents=True, exist_ok=True)
        kernel_artifact.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )
        actor_artifact.write_text(
            json.dumps(actor_result, sort_keys=True) + "\n", encoding="utf-8"
        )
        return {
            "case_name": case_name,
            "fixture_sha256": fixture_sha256,
            "event_id": target_event_ids[0],
            "observed_action": actor_result["observed_action"],
            "actor_exit_code": actor.returncode,
            "kernel_event_count": len(events),
            "kernel_artifact": str(kernel_artifact),
            "actor_artifact": str(actor_artifact),
            "mount": {
                "path": mount.path,
                "filesystem": mount.filesystem,
                "private": mount.private,
            },
        }
    finally:
        if actor is not None and actor.poll() is None:
            actor.kill()
            actor.wait(timeout=5)
        os.close(fanotify_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mount-path", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--kernel-event-artifact", type=Path, required=True)
    parser.add_argument("--actor-result-artifact", type=Path, required=True)
    parser.add_argument("--fixture-sha256", required=True)
    parser.add_argument("--actor-uid", type=int, required=True)
    parser.add_argument("--case-name", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    args = parser.parse_args(argv)
    try:
        result = capture(
            args.mount_path, args.fixture, args.kernel_event_artifact,
            args.actor_result_artifact, args.fixture_sha256, args.actor_uid,
            args.timeout_seconds, args.case_name,
        )
    except (CaptureError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"large-file fanotify capture failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
