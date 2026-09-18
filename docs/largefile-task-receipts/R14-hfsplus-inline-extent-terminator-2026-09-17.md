# R14 — HFS+ inline extent terminator handling

Date: 2026-09-17
Roadmap: `docs/32gb-luna-execution-roadmap.md`, R08
Scope: valid HFS+ forks that continue in the ExtentOverflow B-tree after fewer than eight inline extents.

## Change

`hfsplus_resolve_fork_block()` now treats an all-zero inline extent descriptor as the normal end of the eight-entry inline list. It still rejects half-empty descriptors and any non-zero descriptor after the terminator, validates the remaining inline descriptors before returning a match, and then falls through to the bounded ExtentOverflow lookup when the requested logical block is beyond the inline list.

The existing ExtentOverflow corpus test was tightened so both the data and resource forks contain one inline extent followed by the normal zero terminator and resolve their second block through the matching overflow records. This exercises the valid path that previously returned `CL_EFORMAT` before reaching ExtentOverflow.

## Evidence

- Source guards cover the normal terminator and post-terminator rejection.
- The focused `hfs_fork` test remains registered in `unit_tests/CMakeLists.txt` through the existing `test_hfsplus_extent_overflow_records_are_followed` case.
- The pre-regression-change full source guard suite passed; after the final two assertions were added, direct checks for both new guard strings, snapshot validation, inventory parity, and `git diff --check` passed. The subsequent full guard rerun stalled in the repository harness and was stopped after several minutes without output.
- A compile-only probe reached the preinstalled toolchain but could not start because that image lacks `openssl/opensslconf.h`; the full CMake configure remains blocked by its missing Libcheck/JSON-C prerequisites.
- Linked CTest execution and sanitizer execution remain pending because the local CMake image lacks Libcheck/JSON-C prerequisites and the current-source Sonic1 transfer is still blocked by the MCP-SSH durable-transfer staging limit.

State: implemented; focused-target-registered; qualification-pending.
