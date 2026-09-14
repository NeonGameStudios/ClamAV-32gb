# Task receipt: R08 MBR zero-start partition admission

Task ID / parent milestone: `R08`.

Exact capability under review: `library:mbr-zero-length-partition-admission`.

This receipt records a focused ARM64 development verification. It does not
promote the capability or replace the certified Linux x86-64 qualification
run.

## Source and build identity

- Canonical checkout: `<repository-root>`.
- Branch: `largefile-roadmap-qualification`.
- Base HEAD: `8e837b88c89874b180a1a25f22d287f7d6be29db`.
- Current dirty-source manifest SHA-256: `26b5c4569dc7ae5cf6f3465f93bfd42e0a2a3e074898cd94ebb408550669bfee`.
- Rebuilt ARM64 Release static `check_clamav` SHA-256: `0c2b3016fd99b4d4ddfb2cb195bf03a53bac5a15d5889b085dfe401736a3f74e`.
- The existing dirty working tree was preserved. No reset, clean, commit,
  push, deployment, GitHub workflow action, host package installation, or
  usage-reset action was performed.

## Observed gap and change

The MBR and EBR readers rejected a zero-length partition, but a typed
partition whose first LBA was zero could still be admitted to nested scanning.
That coordinate overlaps the boot record (or the EBR record for a logical
partition), so it must be fail-visible instead of being dispatched as a
supported child.

- Added one shared validation helper for MBR and EBR partition entries. Empty
  entries retain compatibility coordinates, while every typed entry with
  `firstLBA == 0` is rejected with `CL_EFORMAT`, marks the scan incomplete, and
  disables caching through the existing error path.
- Added `test_mbr_zero_start_partition_is_fail_visible`, which constructs a
  typed zero-start MBR entry and asserts the returned error and fail-visible
  context state.
- Added `test_mbr_ebr_zero_start_partition_is_fail_visible`, which constructs
  a typed logical entry at relative LBA zero and asserts the same fail-visible
  result through the EBR path.
- Updated the capability description and source guards so this admission
  rule remains tied to both the primary and logical-partition paths.

## Development verification

- Current-source ARM64 Release focused MBR/EBR case: `mbr` 12/12 checks passed,
  zero failures and errors.
- Current-source ARM64 Release valid MBR corpus: `mbr_corpus` 1/1 passed.
- Current-source ARM64 Release partition-map controls: `partition_map` 5/5
  passed.
- After rebuilding all affected Release targets, the complete current-source
  ARM64 CTest matrix passed 16/16 in 122.00 seconds with zero failed tests.
- `sh tools/largefile_source_guards.sh`: passed after regenerating the
  deterministic inventory and current status snapshot.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md`: passed after regeneration.
- `git diff --check`: passed for the changed implementation, tests, manifests,
  inventory, snapshot, receipt, and ledger.

The release-readiness status remains intentionally blocked: 597 total rows,
0 qualified, 143 bounded, 440 pending, 14 allowlisted unsupported, and 583
release blockers. This focused fix is development evidence only; certified
x86-64, sanitizer, production-CVD/service, full-size, Sonic1, resource, and
R04 qualification evidence remain open. No capability was promoted.

State: `development-verified`; release qualification remains pending.
