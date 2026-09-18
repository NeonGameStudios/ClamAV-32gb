# R12 clamd poll-array and passed-descriptor lifecycle hardening — 2026-09-17 UTC

## Scope

Close two daemon lifecycle failures exposed by the 32 GiB reliability audit:
a failed poll-array resize must not discard the previously valid array, and an
unclaimed descriptor received through ancillary file-descriptor passing must
not leak when its connection is removed or the daemon shuts down.

## Implementation

- `clamd/clamd_others.c::realloc_polldata()` now checks the `pollfd` byte
  product, allocates the replacement first, and releases the old array only
  after replacement allocation succeeds. This preserves a valid cleanup path
  after an allocation failure and resets the cached count during `fds_free()`.
- `fds_cleanup()` and `fds_free()` close any still-owned ancillary descriptor
  (`recvfd`) before releasing its slot.
- `unit_tests/check_clamd_writen.c` now exercises the production poll path with
  an injected resize allocation failure and verifies the old array remains
  available for cleanup. It also verifies an unclaimed passed descriptor is
  closed both when its connection is removed and during daemon-wide teardown.
- The existing zero-progress `writen()` and `fds_add()` allocation-failure
  regressions remain in the same production-linked focused target.

## Verification

- The generated inventory was refreshed from the current source tree.
- `sh tools/largefile_source_guards.sh` passed, including the acceptance map
  check for all 604 capabilities.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` passed.
- Inventory parity and `git diff --check` passed.
- The linked CTest target and sanitizer qualification remain unexecuted because
  the local build prerequisites are unavailable and Sonic1 does not yet hold
  the current source checkout. No capability was promoted to qualified.

State: `implemented; focused-target-registered; qualification-pending`.
