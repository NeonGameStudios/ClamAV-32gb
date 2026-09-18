# Task receipt: R13 Sonic1 fanotify capture primitive — 2026-09-16

Task ID / parent milestone: `R13` / `R04`.

Scope: execute the new real-event capture primitive once in a disposable
privileged Linux container and verify that it records a kernel permission
event and a non-root actor result. This is primitive-level development
evidence only; no clamonacc scan result or R13 capability was promoted.

## Runtime identity

- host: Sonic1, Linux x86-64, MCP-SSH login profile `sonic1-camera-key`;
- source container: `clamav-current-source-20260915`;
- container ID:
  `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`;
- image ID:
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`;
- disposable runtime: `docker run --rm --privileged --user 0` with the
  source bind mounted at `/src`;
- the primitive observed `/src` as a private ext4 mount and marked the path
  with `FAN_EVENT_ON_CHILD | FAN_OPEN_PERM`.

## Real capture result

The current capture script was staged temporarily through the explicit Docker
provenance/exec path, then removed with a successful cleanup command. The
disposable runtime exited 0 and reported:

```text
capture_exit=0
kernel_event_count=1
case_name=clean
event_id=1
observed_action=allow
actor_exit_code=0
actor_uid=65534
mount.filesystem=ext4
mount.private=true
```

The recorded event had `event_kind=FAN_OPEN_PERM`, mask `65536`, metadata
version 3, `event_len=24`, `metadata_len=24`, event FD 4, event PID 7, and raw
metadata hex
`180000000300180000000100000000000400000007000000`. Its target path was
`/src/.codex-r13-fanotify-fixture.bin`, and its fixture digest was
`96a1cd749da450d31e410b6fb33d6d633caf6f04ab0231a98378c383e79a97c8`.
The actor-result record bound the same event ID and digest and reported
`opened=true` with an explicit `FAN_ALLOW` `observer_response` from the
recorder group. This is distinct from the required ClamAV
`permission_response`, which the primitive deliberately does not invent.
The transient artifacts were printed for inspection and removed before the
container exited; they were not presented as retained qualification proof.

## Verification and boundary

- `python3 -B tools/largefile_fanotify_capture_test.py` — 7/7 passed;
- `python3 -B tools/largefile_fanotify_evidence_test.py` — 15/15 passed;
- `sh tools/largefile_source_guards.sh` — passed after the final capture,
  response, and raw-metadata verifier corrections;
- `git diff --check` — passed after the final code and documentation update.

This proves the capture primitive can observe and answer a real Linux
permission event on a supported filesystem. It deliberately does not prove
ClamAV prevention decisions, the six-case matrix, monitoring-only parity,
cleanup of clamonacc/clamd, sanitizer/resource limits, or certified release
qualification. R13 remains open.

State: `development-smoke-verified; capture-primitive-proven`
