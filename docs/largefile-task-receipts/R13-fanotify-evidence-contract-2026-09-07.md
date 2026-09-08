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
