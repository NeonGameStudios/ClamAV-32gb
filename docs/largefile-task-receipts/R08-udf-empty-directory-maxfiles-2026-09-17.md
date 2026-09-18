# R08 — UDF empty-directory MaxFiles admission

Date: 2026-09-17
Roadmap: `docs/32gb-luna-execution-roadmap.md`, R08
Scope: empty nested-directory accounting in the bounded anchored UDF tree.

## Change

The anchored UDF directory walker now sends a recognized directory with zero
information bytes through the shared empty-entry admission path. Empty nested
directories therefore consume the inclusive `MaxFiles` budget just like empty
regular files and cannot return clean while bypassing child accounting.

The UDF corpus regression mutates the standards-shaped root directory fixture
to point at an empty child directory, sets the enclosing layer's count at the
limit, and requires `CL_EMAXFILES`, the canonical
`Heuristics.Limits.Exceeded.MaxFiles` reason, sticky incomplete state, and map
cache taint.

## Evidence

- Source implementation and unit regression were updated in the current
  worktree.
- The capability-manifest validator, release-readiness tests, acceptance-map
  and record checks, snapshot freshness check, inventory parity, and
  `git diff --check` all passed after regenerating derived artifacts.
- The broad `tools/largefile_source_guards.sh` wrapper now uses the repository's
  faster `rg` search path with multi-line matching enabled, and completed with
  `large-file source guards passed`.
- A direct current-source syntax probe could not reach UDF analysis because
  the environment lacks the required `openssl/ssl.h` development header.
- Linked CTest and sanitizer execution remain pending because the local Docker
  runtime and required JSON-C/Check/OpenSSL development prerequisites are
  unavailable. Current-source Sonic1 qualification also remains pending after
  the documented SSH connection timeouts.

State: implemented; focused-target-registered; qualification-pending.
