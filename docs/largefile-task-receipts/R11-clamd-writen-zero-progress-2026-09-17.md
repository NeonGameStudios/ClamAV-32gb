# R11 clamd legacy write-all zero-progress hardening — 2026-09-17 UTC

## Scope

Harden the daemon's legacy `writen()` helper against a successful zero-byte
`write()` result. A non-zero request with no write progress previously
repeated forever, which could pin a clamd thread while a response or payload
was being sent.

## Implementation

- `clamd/clamd_others.c` now treats `write() == 0` while bytes remain as an
  I/O failure, sets `errno` to `EIO`, and returns `-1` immediately.
- The existing `cli_writen()` helper already has the equivalent zero-progress
  contract; this change brings the daemon-local helper into alignment.
- The focused `check_clamd_writen` target compiles the production
  `clamd/clamd_others.c` and verifies a normal pipe write plus an injected
  zero-progress write on Linux using the linker's `write` wrapper.
- `fds_add()` initializes the new slot as inactive and rolls back `nfds` when command-buffer allocation fails, so an OOM path cannot publish an uninitialized descriptor.
- The same focused target injects that allocation failure and verifies the descriptor list remains empty.

## Verification

- The source guard suite requires the zero-progress branch, `EIO` result,
  focused target, and injected assertion.
- Strict local compilation of the test translation unit is limited by the
  checkout's generated `clamav-types.h` build dependency; the full target is
  wired for the configured CMake build.
- The production-linked CTest and sanitizer qualification remain unexecuted
  because the available local dependency image cannot configure the current
  tree and Sonic1 does not hold the current source.

State: `implemented; focused-target-registered; qualification-pending`.
