# R03 — Sonic1 registered CTest regression

Date: 2026-09-19
Task ID / parent milestone: `R03` / current-source runtime regression

## Evidence identity

- Local candidate branch: `largefile-roadmap-qualification`
- Local candidate HEAD: `7f0f6334`
- Host: `sonic1`, login profile `sonic1-camera-key`
- Container: `clamav-current-7f3458c4`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Image: `clamav-32gb:dev-current`
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Build directory: `/tmp/clamav-7f3458c4-build`

The remote container exposed the rebuilt source tree at `/src`. The source
guard file in that remote tree was an older copy (`42cbf9ad...843edeb`), while
the current local source guard is `e8f169a1...884208c`; this identity mismatch
is retained as part of the result rather than silently treating the remote
tree as the local candidate.

## Registered suite

The build registered 31 CTest targets. The tracked async job
`job_f3b0618291744523afc11d0a6a2d3282` ran serially with
`--output-on-failure` and completed in 214.10 seconds:

```text
30/31 tests passed
exit: 8
```

The following runtime and control groups passed: on-access threadpool and
configuration admission, clamd threadpool and writen, milter controls,
`libclamav`, fail-closed POC, runtime/service evidence checks, acceptance
schemas and producers, clamscan admission, clamd report protocol, ZIP late
member, on-access stream deadline, procfs RSS/metrics/OOM controls, milter
quota/protocol, `libclamav_rust`, `clamscan`, `clamd`, `freshclam`, and
`sigtool`.

## Sole failure and reconciliation

The only failure was test 9, `largefile_source_guards`:

```text
large-file source guard failed: libclamav/matcher-bm.c does not contain:
cli_qsort(data->offtab, data->cnt, sizeof(uint64_t), cli_bm_uint64_cmp)
```

The remote source file does contain that exact line. The minimal container has
no `rg`, while the guard invokes `rg` and suppresses its command error, turning
missing tooling into a false “pattern absent” result. The current local
source guard was run independently and passed:

```text
large-file capability manifest passed (604 entries)
large-file release readiness tests passed
large-file source guards passed
```

The remote source tree was not promoted or used to claim qualification. No
software was installed into the container.

## Boundary

This is broad current-build development regression evidence, not certified
Linux x86-64 Release/sanitizer parity, materialized 32-GiB qualification, R04
capability-bound acceptance, R13 real fanotify evidence, or release evidence.

State: `development-verified-with-test-environment-gap`; qualification pending.
