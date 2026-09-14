# R10 milter send deadline and spool-write retry — 2026-09-11

Task ID / parent milestone: `R10` / `R00`

Exact capability kind:id list: `milter:message`

Observed gaps: the nonblocking milter `nc_send()` helper recreated its
30-second deadline after every successful partial `send()`, allowing a large
payload to wait indefinitely while the peer made incremental progress. The
local temp-file branch in `sendchunk()` also treated a signal-interrupted
`write()` as a permanent spool failure.

Implemented slice:

- `clamav-milter/netcode.c` now establishes one deadline before the complete
  send loop and computes each readiness wait from the remaining budget.
- `clamav-milter/clamfi.c` retries local spool writes interrupted by `EINTR`
  without discarding the in-progress message.
- The milter capability wording and source guards bind both guarantees.

Evidence:

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — 147 passed,
  2 expected skips.
- `sh tools/largefile_source_guards.sh` — passed with 597 capability
  bindings, including refreshed inventory/snapshot and acceptance controls.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md`
  and regenerated-inventory comparison — passed.
- `git diff --check` — passed.
- Stable source-manifest SHA-256 (two consecutive generations):
  `2e00bba6b8dadca33d8d5e17eca3679018ca48c37215ab4ab8d5ac1dcc98429a`.

No capability was promoted. Current-source linked milter execution, certified
Linux x86-64, full-size service parity, sanitizer, production-CVD, R04
acceptance, and final release qualification remain open. No remote execution,
remote SSH, usage reset, commit, push, or GitHub workflow action was used.

The corrected checkout also passed the full host suite (147 passed, 2
expected skips), the 597-binding source guard sweep, inventory freshness,
snapshot validation, and `git diff --check`. Its current source-manifest
SHA-256 is
`cd5a9c391c706e45b9b7f9bc58d908b39a85e6e32c8bd403187bcb9349467eeb`.

Follow-on end-to-end deadline enforcement (2026-09-11 UTC): `nc_send()` now
checks the established deadline before every `send()`, covering the otherwise
unbounded case where a writable nonblocking socket accepts repeated partial
writes without entering the `EAGAIN` readiness wait. The ten changed ingress
translation units still pass warning-as-error syntax checking in the disposable
Docker toolchain; host tooling passes 147 tests with 2 expected skips, source
guards pass for 597 bindings, regenerated inventory/snapshot checks and
`git diff --check` pass. The refreshed source-manifest SHA-256 is
`7367697b6324da35cfa800e0f42c280b208f8ed9e6266e1b943411b907d935f7`.
This remains development evidence only; no linked milter runtime,
qualification, or capability promotion is claimed.

Follow-on FD-passing deadline enforcement (2026-09-11 UTC): `nc_sendmsg()` now
checks the established deadline before each `sendmsg()` retry, including
repeated `EINTR` retries that do not enter the `EAGAIN` wait path. The focused
warning-as-error syntax check, 597-binding source guards, 147-test host suite
with 2 expected skips, regenerated inventory/snapshot checks, and
`git diff --check` pass. The refreshed source-manifest SHA-256 is
`77146a74752dec7e1bc49b30d32af4193ca46a86c92ff3a9df905690aab3981b`.
No linked milter runtime, qualification, or capability promotion is claimed.

Follow-on guard precision (2026-09-11 UTC): the source guard was tightened to
require that the deadline check precede the actual `send()` and `sendmsg()`
calls, preventing the existing readiness-wait check from masking removal of
the new pre-send enforcement. The guard sweep, host suite (147 passed, 2
expected skips), warning-as-error milter syntax check, refreshed
inventory/snapshot checks, and `git diff --check` pass. The resulting
source-manifest SHA-256 is
`07b9f9b1f92a71c9b361f004de4b3c5e0de413821231a3d4c4bb2adada8ce4d8`.

Follow-on current-source compile correction (2026-09-11 UTC): restoring the
`nc_send()` error-log scratch buffer fixed a compile-time use of the shared
`strerror_print` macro that the initial slice had accidentally left without
its required local storage. The disposable `rust:1.97-bookworm` toolchain
passed a warning-free `-fsyntax-only` check for `clamav-milter/netcode.c` using
a temporary JSON type stub; no dependency was installed. The source guard now
binds the buffer to the milter send error branch.
