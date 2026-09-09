# Task receipt: R13 fanotify permission evidence contract

Task ID / parent milestone: `R13` / `R04`

Scope: define and enforce the retained evidence contract for the
`on-access:permission` capability. This slice does not claim a Linux fanotify
run and does not fabricate kernel-event evidence.

Changes made:

- Added `tools/largefile_fanotify_evidence.py`, a standard-library verifier for
  a private Linux permission-event mount, prevention-mode clean/detection/
  limit/resource/timeout/parser outcomes, a separate monitoring-only matrix,
  source/build/config identity hashes, retained artifact hashes, and complete
  process/fanotify/mount/fixture/temporary-path/daemon cleanup.
- Wired authoritative release readiness to require and validate
  `provenance/fanotify-permission-evidence.json` whenever
  `on-access:permission` is marked qualified. Missing fanotify evidence now
  fails closed even if a generic capability proof is present.
- Added focused tamper, missing-case, wrong-decision, non-Linux, and cleanup
  regression tests, plus a release-gate regression proving a generic proof
  cannot qualify on-access without the fanotify proof.
- Hardened the Linux fanotify event loop so every `select()` wait rebuilds its
  descriptor set. This prevents an idle or interrupted wait from carrying
  forward a mutated empty `fd_set` and silently missing later permission
  events.
- Hardened the fanotify read boundary so `errno` is examined only for a
  failed `read()`. A recoverable `EOVERFLOW`, `EMFILE`, or `EACCES` can no
  longer be carried into the next successful event batch and cause valid
  permission events to be skipped.
- Hardened queue failure handling: queue and worker-pool initialization now
  fails visibly, an event submitted before queue initialization is rejected
  without leaking its queue node, and a worker-pool job-allocation failure
  processes the already-owned event inline so its permission response and
  descriptor cleanup still occur.

Verification:

- `python3 -B tools/largefile_fanotify_evidence_test.py` — 9 tests passed.
- `sh tools/largefile_release_readiness_test.sh` — passed.
- `sh tools/largefile_source_guards.sh` — passed, including the 597-row map,
  snapshot freshness, existing producer/runtime/service/boundary suites, and
  the new fanotify suite.
- `sh -n tools/largefile_release_readiness.sh` — passed.
- Existing disposable Linux toolchain syntax checks for
  `clamonacc/fanotif/fanotif.c` and `clamonacc/scan/onas_queue.c` — passed.
- `git diff --check` — passed.

Evidence state and blocker: no real fanotify permission evidence was produced.
The current macOS/ARM64 development environment cannot provide the authorized
Linux kernel permission-event run required by R13. The release readiness gate
therefore remains blocked until a certified Linux x86-64 runner produces and
retains this proof alongside the current-source build identity.

State: `development-verified`

Follow-on fail-closed event-release correction (2026-09-08): fanotify
permission events that fail before queue ownership—read-link failure, event
allocation, context mapping, metadata-copy, metadata-version validation, or
queue admission—now receive `FAN_DENY` before their kernel metadata descriptor
is closed. Queue admission failures do not retry a permission event after
replying; non-permission queue failures retain the existing retry behavior.
The current-source ARM64 `clamonacc` target was rebuilt and linked in a
disposable container after installing only the missing development headers
inside that container. The target compiled successfully, including the
changed `fanotif.c` unit; version/help startup could not be used as a runtime
smoke because this build requires a full clamd configuration and fanotify
startup. Real permission-event evidence remains blocked on the authorized
Linux x86-64 runner.

Follow-on worker response-boundary correction (2026-09-08): the normal
permission-response path now retries an interrupted `write()`, rejects short
writes as `CL_EWRITE`, and invokes the shared `FAN_DENY`/close recovery path
when the kernel does not accept the complete response. A malformed queued
event with no metadata descriptor or invalid fanotify descriptors now returns
`CL_EARG` instead of dereferencing missing event state. Cleanup skips a
descriptor already released by the fallback path. This closes a local
fail-closed response gap; it does not create privileged fanotify evidence.

The shared fallback denial helper also retries an interrupted kernel response
write, so the worker and pre-queue recovery paths share the same `EINTR`
handling before descriptor cleanup. This removes the remaining local response
delivery hole; privileged Linux fanotify evidence is still unrun.

The malformed-context guard was then tightened to release a still-valid
metadata descriptor through the same denial/close helper before returning, so
invalid fanotify channel state cannot turn validation failure into a leaked or
blocked permission event.

Follow-on excluded-event response correction (2026-09-08): the permission
event path for excluded files now retries an interrupted `FAN_ALLOW` write and
routes a short or failed write through the existing `FAN_DENY`/close recovery
path. This keeps transient `EINTR` from causing an unnecessary denial while
ensuring a partial kernel response cannot become an implicit allow. The
source/evidence controls pass; real privileged fanotify qualification remains
blocked on the authorized Linux x86-64 runner.

The isolated current-source fanotify object compile was attempted in the
existing disposable ARM64 build tree and stopped before compiling the changed
translation unit because `/usr/include/openssl/ssl.h` includes the absent
`openssl/opensslconf.h`. No dependency was installed or downloaded; the
source/evidence controls remain the available verification for this slice.
