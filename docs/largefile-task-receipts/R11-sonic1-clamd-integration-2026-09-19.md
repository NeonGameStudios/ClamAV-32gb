# R11 — Sonic1 current-source clamd integration

Date: 2026-09-19
Task ID / parent milestone: `R11` / daemon ingress

## Evidence identity

- Branch: `largefile-roadmap-qualification`
- Source commit: `c6de97b9`
- Host: `sonic1`, login profile `sonic1-camera-key`
- Container: `clamav-current-7f3458c4`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Image: `clamav-32gb:dev-current`
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Build directory: `/tmp/clamav-7f3458c4-build`
- Source bind: `/src` → `/tmp/clamav-32gb-7f3458c4` (read/write)

The container provenance reported the rebuilt source bind mounted at `/src`.

## Supported wrapper

The repository CMake test invokes the Python module through unittest. The
equivalent remote invocation was:

```text
python3 -m unittest clamd_test.py
```

with `SOURCE=/src`, `BUILD=/tmp/clamav-7f3458c4-build`, an isolated `TMP`,
`CHECK_CLAMD`, `CLAMD`, `CLAMDSCAN`, `CLAMSCAN`, `VERSION`, and
`CVD_CERTS_DIR` explicitly bound to the current build and checked-in fixtures.

## Runtime results

The supported daemon integration wrapper exited successfully after exercising
the daemon lifecycle and client ingress paths:

```text
clamd startup: success
clamdscan PING/PONG: success
clamdscan version: ClamAV 1.5.3-largefile-devel
reload before/after detection: success
file, multiscan, stream, and fdpass modes: success
```

The embedded `check_clamd` report was:

```text
100%: Checks: 121, Failures: 0, Errors: 0
```

The stderr lines from malformed-limit and over-limit cases are expected
negative-path assertions in this suite, including the 32-GiB upper-bound
checks. The final post-test PING returned `PONG`.

## Boundary

This proves current-source daemon startup, reload, client ingress, stream and
file-descriptor paths, and the complete supported `clamd` regression wrapper
on Sonic1. It is development integration evidence, not the exact fully
allocated 32-GiB qualification run, R04 acceptance evidence, or release
evidence.

State: `development-verified`; qualification pending.
