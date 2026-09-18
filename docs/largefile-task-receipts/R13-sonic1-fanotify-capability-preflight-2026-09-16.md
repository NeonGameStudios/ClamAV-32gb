# Task receipt: R13 Sonic1 fanotify capability preflight — 2026-09-16

Task ID / parent milestone: `R13` / `R00`.

Scope: determine whether the Sonic1 Linux x86-64 Docker execution path can
initialize the real fanotify interface needed for the R13 permission-event
matrix. This is a capability preflight only. It does not claim a permission
allow/deny event, a private test mount, a clamd/clamonacc matrix, or release
qualification.

## MCP-SSH extension used

The documented MCP-SSH tracked asynchronous path was used with host `sonic1`,
login profile `sonic1-camera-key`, typed Docker arguments, and the effective
600-second timeout. Each foreground probe was represented by a tracked job and
was allowed to reach a terminal state; no detached daemon or untracked
background process was left running.

## Evidence

The current test container was:

- name: `clamav-current-source-20260915`;
- container ID: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`;
- image: `clamav-32gb:dev-current`;
- image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`;
- platform: Linux `x86_64`;
- source HEAD: `08b3ab820e40ac8bd307290b0c78c03c94884f1b`, with a dirty checkout.

The non-root and root-prefixed probes in that container both returned the
actual clamonacc diagnostic:

```text
ERROR: Clamonacc: fanotify_init failed: Operation not permitted
ERROR: Clamonacc: clamonacc must have elevated permissions ... exiting ...
```

The root-prefixed probe was tracked as job
`job_8866db80ecb74fe686987b8492e716d8` and exited `2`. The source code's
startup order calls `fanotify_init()` before the clamd connection check, so
this is direct evidence that UID 0 in the ordinary container is still missing
the kernel capability.

A disposable `docker run --rm --privileged` probe was then executed with the
already-built `clamonacc` binary, its resolved `libclamav` and `libclammspack`
dependencies, and an explicit scoped clamd configuration. The final tracked
job was `job_3fa12956d0f34db8803a6d6e4e34c70c`; it exited `2` with:

```text
ERROR: ClamClient: Could not connect to clamd, Couldn't connect to server
ERROR: Clamonacc: daemon is local, but a connection could not be established
```

No `fanotify_init` error was emitted in that privileged run. Because
`fanotify_init()` precedes the connection check, the result establishes that
the `--privileged` Docker execution path can initialize fanotify on Sonic1.
The disposable container used `--rm` and was removed by Docker; temporary
staged binaries and configuration were removed after the probe.

## Boundary and next task

This preflight narrows the blocker: the existing development container lacks
fanotify permission, while an explicitly privileged disposable container can
pass the kernel initialization step. R13 remains open. The next valid slice
is a real privileged runner that starts a scoped clamd, creates a private test
mount, runs clamonacc, records kernel permission allow/deny events for the
required outcomes, and proves cleanup. The preflight itself is not substituted
for those events.

State: `capability-preflight-passed; permission-matrix-not-run`
