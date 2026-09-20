# Task receipt: R13 Sonic1 runtime runner and capability blocker — 2026-09-20

Task ID / parent milestone: `R13` / `R04`.

## Implementation

Added `tools/largefile_fanotify_runtime_runner.py`, a one-case-per-invocation
runner for authorized Linux runtimes. It starts the real `clamd` and
`clamonacc` binaries, retains daemon/client logs, health and cleanup state,
invokes the independent fanotify observer for prevention cases, selects the
matching structured report event, and calls the existing fail-closed case
binder. It also supports a separate monitoring-only actor path. The runner
refuses to overwrite an output directory, refuses runner-owned configuration
overrides, records the effective configuration and fixture hash, and includes
daemon/client diagnostics when startup fails.

Added `tools/largefile_fanotify_runtime_runner_test.py` with three helper
tests, source-guard coverage, and the runner command entry point in the
roadmap. Local checks passed:

- `python3 -B tools/largefile_fanotify_runtime_runner_test.py` — 3/3;
- `git diff --check`;
- `sh tools/largefile_source_guards.sh` — 604-entry manifest, readiness,
  acceptance, fanotify, runner, and source-guard suites passed.

## Sonic1 execution

The execution used host `sonic1` with login profile `sonic1-camera-key`, the
current-source Sonic1 container `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`,
image `clamav-32gb:dev-current` with image ID
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`,
source HEAD `aa6c0077130c9f7aefd8d366aa9a689ffc6c87fe`, and source manifest
SHA256 `f7be88d8961ee5e5546e5fbcf44374a70c083deccbb34ba867547a9cd6aacf8f`.
The exact Release binaries were staged temporarily from the existing source
container; the staged build and runner were removed and their exact paths
verified absent after testing.

The daemon admission observations were fail-visible and consistent with the
measured host capacity:

- certified `MaxTemporarySize 64G`: `temporary_free=36920852480` bytes,
  `required=73014444032` bytes;
- development `40G`: `temporary_free=36920791040`,
  `required=47244640256`;
- development `32G`: `temporary_free=36920725504`,
  `required=38654705664`;
- development `30G`: daemon admission passed, allowing the client capability
  probe to run.

At the `30G` development setting, the real client exited with:

```text
ERROR: Clamonacc: fanotify_init failed: Operation not permitted
ERROR: Clamonacc: clamonacc must have elevated permissions ... exiting ...
```

An independent direct syscall probe returned `fd -1 errno 1` under both
`docker run --privileged` and the additionally unconfined disposable security
profile. No ClamAV permission-event artifacts were accepted or generated from
these failed attempts. The runner therefore remains implementation-verified,
but Sonic1's current Docker/kernel capability boundary is an external blocker
for running the real R13 fanotify matrix in this environment.

No software was installed, no production deployment was changed, and no
capability was promoted. Full-size resource, PCRE phase, six-case prevention,
monitoring-only matrix, sanitizer, and final release evidence remain open.

State: `development-verified; fanotify-capability-blocked-on-sonic1`
