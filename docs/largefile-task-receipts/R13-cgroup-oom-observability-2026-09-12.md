# Task receipt: R13 cgroup-v2 OOM observability — 2026-09-12

## Scope

The service resource gate now needs direct evidence that no OOM or OOM-kill
counter increased during a run. Process liveness alone cannot establish that
property, so this slice adds a cgroup-v2 `memory.events` baseline and final
comparison.

## Changes

- Added `tools/largefile_procfs_tree_oom.py`, which resolves the cgroup-v2
  membership of each service root, reads the distinct cgroups' `oom` and
  `oom_kill` counters, and emits a SHA-256 identity for the selected cgroup
  set. Missing cgroup-v2 observability fails closed.
- Added a real Linux regression for counter parsing and duplicate-cgroup
  de-duplication. The service gate captures the runner baseline, requires
  stable cgroup identity during every resource sample, retains the counters in
  each resource row, and checks the final post-cleanup counters against the
  baseline.
- Extended the independent service evidence verifier and synthetic evidence
  regression to require zero OOM/OOM-kill delta, stable cgroup identity, and
  the exact counter-sample schema.

## Verification

- `python3 -B tools/largefile_procfs_tree_oom_test.py` in the existing Linux
  Rust image — passed against real cgroup-v2 `memory.events`.
- `sh tools/largefile_service_evidence_check_test.sh` — passed, including the
  non-zero OOM/swap rejection contract.
- Reconfigured the existing ARM64 Release development build and ran focused
  CTest — `4/4` passed: `largefile_source_guards`,
  `largefile_service_evidence_check`, `largefile_procfs_tree_metrics`, and
  `largefile_procfs_tree_oom`. Retained log:
  `/private/tmp/clamav-r13-oom-focused-20260912.log`, SHA-256
  `0834965d39db0774f5c1893272b4fd83c4b0b14ee4e5d10745b3863c37a1b4ba`.
- Final post-identity-binding focused log:
  `/private/tmp/clamav-r13-final-focused-20260912.log`, SHA-256
  `f75cf7b5d94ad45158adc7a88949db2d0a1319146b408d6b72dffa20538e39f1`.
- Current source manifest SHA-256:
  `e10f52fa7a6fa26bf32f4a1fb61061a0c0173027b78e4200d5e61679d5bf3eb3`.
  The tracked inventory remains 44,674 lines, SHA-256
  `c38bf34d1f45d55640bed835724b322e162c914d745160f9e3d0833f3dc3aab4`.
- `git diff --check` exits 0; no commit or push was made.

## Qualification boundary

This is development resource instrumentation, not release qualification. The
run used ARM64 development infrastructure and a small process tree, not the
certified Linux x86-64 full-size production service workload. The gate now
has direct cgroup-v2 OOM-counter evidence where that kernel observability is
available, but PCRE phase qualification, per-parser R14 canary metrics,
sanitizer parity, full-size materialized inputs, production CVDs, Sonic1,
real fanotify permission responses, and final readiness remain open.
