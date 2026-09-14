# Task receipt: R13 process-tree memory and I/O metrics — 2026-09-12

## Scope

The service qualification runner previously retained only aggregate process-tree
`VmRSS` and temporary-directory usage. The roadmap also requires resident-set
and operational resource evidence that can identify swap use and cumulative
fault/I/O behavior. This slice adds a fail-closed Linux procfs sampler and
binds its complete sample rows into the service producer and independent
verifier.

## Changes

- Added `tools/largefile_procfs_tree_metrics.py`, which walks the supplied
  service roots and descendants and sums `VmRSS`, `Pss` from `smaps_rollup`,
  `VmSize`, `VmSwap`, minor/major faults from `/proc/<pid>/stat`, and read,
  write, and cancelled-write bytes from `/proc/<pid>/io`.
- The sampler preserves process topology independently of metric reads and
  fails if any selected process lacks a required metric; a missing descendant
  cannot silently disappear from the aggregate.
- Extended `provenance/service-resource-samples.tsv` with the memory, swap,
  page-fault, and I/O columns. The service gate now requires zero observed
  process-tree swap, validates PSS/VAS relationships and budgets, and records
  the corresponding peaks in `service-summary.txt`.
- Extended `largefile_service_evidence_check.sh` and its regression fixture to
  validate the exact schema, all counter peaks, zero swap, PID-set identity,
  and the sampler identity. Added a real parent/child Linux regression and a
  CTest registration.

## Verification

- `python3 tools/largefile_procfs_tree_metrics_test.py` on macOS — exited 0
  with the expected Linux-procfs-unavailable skip; direct invocation fails
  closed on this non-Linux host.
- `docker run --rm -v /Volumes/512gbNVME/github-external/ClamAV-32gb:/src -w
  /src rust:1.97-bookworm python3 -B
  tools/largefile_procfs_tree_metrics_test.py` — passed in the existing Linux
  development container against a real parent/child process tree.
- `sh tools/largefile_service_evidence_check_test.sh` — passed, including the
  non-zero-swap rejection regression.
- Reconfigured existing ARM64 Release build and ran focused CTest — `3/3`
  passed: `largefile_source_guards`, `largefile_service_evidence_check`, and
  `largefile_procfs_tree_metrics`. Retained log:
  `/private/tmp/clamav-r13-metrics-focused-20260912.log`, SHA-256
  `f73414d70e3c04da6d3561416c8cfb7810147b076d1743e45346aadf9f4f36a4`.
- Current source manifest SHA-256:
  `f8130229ca77715c899163e61172416aaec77ad1b0f90c32347d0e5047cffa8a`.
  The tracked inventory remains 44,674 lines, SHA-256
  `c38bf34d1f45d55640bed835724b322e162c914d745160f9e3d0833f3dc3aab4`.
- `git diff --check` exited 0; only the repository's existing CRLF
  normalization warnings are present. No commit or push was made.

## Qualification boundary

This is development tooling and verifier evidence, not a qualification result.
The run used ARM64 development infrastructure, not the certified Linux x86-64
runner or a full-size production-CVD service workload. It records aggregate
PSS/VAS/swap/fault/I/O metrics but does not yet provide per-parser R14 canary
records, historical OOM-event proof, PCRE phase evidence, real fanotify
permission responses, sanitizer parity, or release readiness.
