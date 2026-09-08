# Task receipt: R13 on-access lifecycle and PCRE phase contracts

Task ID / parent milestone: `R13` / `R04`

Scope: close five bounded reliability and evidence gaps identified while
bringing the on-access and PCRE roadmap paths toward qualification. This
slice does not claim a certified Linux run or fabricate runtime evidence.

Changes made:

- Queue startup now publishes `STARTING`, `READY`, and `FAILED` states and
  blocks the caller until the event queue and worker pool are actually usable.
  Initialization failures are returned to `clamonacc` instead of allowing the
  fanotify loop to run against an unready queue.
- Inotify waits rebuild their `fd_set` before every `select()` call, matching
  the fanotify fix and preventing an interrupted or idle wait from silently
  losing the descriptor. Valid descriptor 0 is accepted, watch-table growth
  uses the correct native allocation size and full-range initialization, and
  kernel watch removal and event-descriptor lookup fail safely.
- Inotify extra-scan allocation, context mapping, pathname duplication, queue
  submission, watch-table growth, and setup failures now have fail-visible
  cleanup paths. Path-list allocations and partial DDD state are released on
  both setup failure and normal thread shutdown.
- `clamonacc` now initializes descriptors to `-1`, closes them conditionally,
  and stops/join worker threads before freeing the shared context on normal
  exits as well as signal exits.
 the original `readlink()` failure across descriptor cleanup, and treats
 context-to-event mapping failure as a fail-visible event rejection with
 descriptor cleanup instead of dereferencing an unchecked result.
- Fanotify event handling now initializes its descriptor sentinel, preserves
  the original `readlink()` failure across descriptor cleanup, and treats
  context-to-event mapping failure as a fail-visible event rejection with
  descriptor cleanup instead of dereferencing an unchecked result.
 `stat()`; if the event path disappears, the fail-closed permission
 response path no longer passes an indeterminate status structure by value.
- The on-access file worker now zero-initializes its `STATBUF` before
  `stat()`; if the event path disappears, the fail-closed permission
  response path no longer passes an indeterminate status structure by value.
- The inotify watch-list loop now advances its index when it deliberately
  skips `/` or clamd's temporary directory, and no longer dereferences the
  unrelated option-list cursor on those branches.
- Added `tools/largefile_pcre_phase_evidence.py`, a fail-closed verifier for
  the PCRE 40-GiB subject phase and strict post-PCRE under-12-GiB phase. It
  requires ordered process-tree RSS samples, exact-tail detection proof,
  runtime phase transitions, source/build/config identities, and retained
  artifact hashes. The release gate requires this proof for any qualified
  `matcher:pcre` row.

Verification:

- `python3 -B tools/largefile_pcre_phase_evidence_test.py` — 8 tests passed.
- `python3 -B tools/largefile_fanotify_evidence_test.py` — 9 tests passed.
- `python3 -B tools/largefile_runtime_acceptance_case_producer_test.py` — 4
  tests passed.
- `sh tools/largefile_release_readiness_test.sh` — passed.
- `sh tools/largefile_source_guards.sh` — passed, including the 597-row case
  map, release gate, snapshot freshness, evidence-contract, and producer
  regressions.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` — passed.
- Existing disposable `rust:1.97-bookworm` GCC syntax checks for
  `clamonacc/clamonacc.c`, `clamonacc/fanotif/fanotif.c`,
  `clamonacc/inotif/inotif.c`, and `clamonacc/scan/onas_queue.c` — passed
  using the pre-existing syntax-only JSON header stub and repository headers.
- The warning-focused syntax audit of the same four units also passed; its
  only diagnostic is the known declaration-only `cli_dbgmsg` warning from the
  syntax stub.
- `largefile_clamd_report_protocol_test.py` now selects a valid configured
  temp directory or the platform default; the protocol regression passes on
  both the host and the disposable container.
- `git diff --check` — passed.

Follow-on current-source link check: the existing ARM64 static test build has
`ENABLE_CLAMONACC=ON` and supplied the unchanged client objects and static
libraries. The four changed on-access units (`clamonacc.c`, `fanotif.c`,
`inotif.c`, and `onas_queue.c`) were recompiled from this worktree with the
pre-existing `rust:1.97-bookworm` GCC toolchain and linked into a fresh
`clamonacc` ELF in `/private/tmp`. The link used the pre-existing temporary
JSON-C library and declaration-only header stub only to bridge the absent
development header; it did not install or download a dependency. The fresh
binary SHA-256 is
`79a0655a09d20c66176d14a47a4b148c4a7dbcd854c701978baa1920e2616300`.
Its help/configuration path parsed a temporary clamd configuration and
reported version `1.5.3-largefile-devel`. This is stronger than syntax-only
evidence for the changed on-access units, but it is not a full current-source
CMake rebuild because the unchanged client objects and static libraries come
from the earlier development build; privileged fanotify permission-event
execution was attempted and failed at `fanotify_init` with
`Operation not permitted` in the unprivileged container.

The same fresh binary was then exercised in a privileged disposable
`rust:1.97-bookworm` container with the existing ARM64 `clamd`, a temporary
valid clamd configuration, and the repository's custom signature directory.
`clamonacc -c /out/clamd.conf -p 1 -F` initialized fanotify, connected to the
daemon, printed `PONG`, and returned exit code 0. This validates the current
on-access startup/client handshake and the revised descriptor/queue lifecycle
through the daemon boundary; it is not a permission-event scan because the
test stops at the ping action, and it does not replace a full current-source
CMake rebuild or certified x86-64 evidence.

The setup-failure path was also run with a current-source rebuild after
fanotify setup rejected the container's tmpfs mark with `EINVAL`. The process
returned exit code 2 within the bounded wait, logged the exact mark error, and
logged `ClamScanQueue: stopped`; it no longer hangs while joining the queue
consumer after cancellation from `pthread_cond_wait()`. This regression uses
the current queue object and is development evidence only; it does not claim
that the container filesystem can provide the required production permission
events.

Environment limitation: the existing disposable Docker images do not contain
the complete JSON-C development package needed for a coherent full
current-source CMake rebuild or runtime run. No software was installed. The
focused link check above used the real pre-existing runtime library, while the
declaration-only stub was limited to parsing the four changed units; the
source-guard and focused behavioral/evidence checks remain the authoritative
local verification for this slice.

The registered disposable CTest integration run initially passed 5/7
controls. The protocol-test failure was corrected by the portable temp-path
change above and now passes in the container. The remaining clamscan control
cannot start its existing binary because the image lacks `libjson-c.so.5`; no
stale binary result was used as current-source qualification.

Evidence state and blocker: development-verified. Real Linux fanotify
permission-event evidence and real PCRE phase RSS evidence remain required
from the authorized qualification runner before R13 or release readiness can
be promoted.

State: `development-verified`
- The inotify watch-list loop now advances its index when it deliberately
  skips / or clamd's temporary directory, and no longer dereferences the
  unrelated option-list cursor on those branches.
- The inotify path-list reader now rejects empty entries safely, preserves
  final lines without a newline, uses getline()-width types, and returns
  CL_EREAD after a file-read failure instead of accepting a partial list.
