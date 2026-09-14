# Task receipt: R10 clamd thread-pool admission — 2026-09-12

Task ID / parent milestone: `R10` / daemon ingress and scheduling.

Exact capability kind:id list: `service:clamd` and the shared clamd worker-queue
admission contract. This receipt does not promote any capability to release
qualification.

Starting commit and working-tree/source manifest identity: starting commit
`8e837b88`; the worktree already contained the roadmap implementation and
uncommitted task files. The post-change source manifest contains 1,696 entries
and is SHA-256
`9d9c01e047b48b64d127ea9eea68feb96d769a70da1783998bb07494eada79dc`.

Prerequisites verified: the existing `rust:1.97-bookworm` ARM64 development
container was reused with the current checkout mounted at `/src`. The existing
Release build at `/tmp/clamav-release-current-20260912` was regenerated and
reused. No software was installed.

Observed failing case and expected behavior: `thrmgr_dispatch_internal()`
previously added a request to a work queue and then ignored `pthread_create()`
failure. If no idle worker existed, the request could remain queued forever
while dispatch reported success. Admission must start a required worker before
publishing the queue item, reject worker-start failure, and restore a consumed
reservation when a reserved dispatch cannot be admitted.

Changes made:

- Start a required clamd worker before queue insertion and return failure when
  `pthread_create()` fails.
- Restore reserved capacity and wake queueable waiters when reserved admission
  or queue insertion fails.
- Reject non-positive clamd queue capacities at pool construction.
- Add a Linux linker-wrapped `EAGAIN` regression covering ordinary dispatch,
  reserved-dispatch retry, and normal callback execution.
- Register the regression in CTest, add source guards, and refresh the tracked
  inventory.

Commands, exits, and hashes:

- Regenerate CMake and build `check_clamd_threadpool` — exit 0.
- Build production `clamd` — exit 0.
- Direct focused regression — exit 0; both injected worker-create failures
  were logged as `dispatch rejected`.
- Focused CTest for clamd and on-access pool controls — `3/3` passed.
- Complete configured current-source ARM64 Release CTest matrix — `27/27`
  passed in `175.01` seconds.
- Final `sh tools/largefile_source_guards.sh` — exit 0.
- Final snapshot freshness check — exit 0.
- `git diff --check` — exit 0.
- Tracked inventory: 44,703 lines, SHA-256
  `e6d41aab63fe844e60b8544fd47625cc34371e4fc241f8912520bf8ac6bb5d43`.
- Rebuilt `clamd` SHA-256:
  `70b385dde49340c6dafd2206e31da12e16eeb70aab5de01762863eefc018d2ba`.
- Rebuilt threadpool regression SHA-256:
  `ac80a018c13fbb0dedfc90b20d2dd98a13c06ecd9c8282c5bb2fa0538fc57301`.

Full-size/certified evidence produced, or explicitly not run: not produced;
the available container is Linux ARM64 and cannot satisfy the roadmap’s
certified Linux x86-64, exact 32-GiB, sanitizer, production-CVD, Sonic1,
resource-sidecar, or privileged fanotify permission requirements.

State: `development-verified; qualification-blocked-by-runner-and-fixtures`.
