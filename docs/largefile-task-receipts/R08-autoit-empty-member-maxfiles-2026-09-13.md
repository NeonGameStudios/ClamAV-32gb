# Task receipt: R08 AutoIt empty-member MaxFiles accounting — 2026-09-13

Task ID / parent milestone: `R08` / `R00`

## Scope

Close the AutoIt EA05 and EA06 paths that skipped a declared zero-byte member
without charging inclusive `MaxFiles`. An empty AutoIt member has no payload
to materialize, but remains a logical child for nested admission.

Exact capability kinds and IDs: `parser:CL_TYPE_AUTOIT`,
`library:nested-scan-empty-completion`.

## Observed defect

A valid in-memory archive containing two empty members returned `CL_SUCCESS`
with the root already consuming one slot and `MaxFiles=2`. The second child
must fail with `CL_EMAXFILES` (`25`). The pre-fix production-linked Release
regression reproduced the false success (`0`).

## Implementation

- AutoIt EA05 now calls `cli_updatelimits(ctx, 0)` before advancing past an
  empty member.
- AutoIt EA06 applies the same logical-child admission boundary.
- Configured-limit failures are returned immediately and non-terminal limit
  failures mark the scan incomplete, preventing a false clean/cacheable result.
- Added a production-linked regression covering two empty members in both
  AutoIt formats; regenerated the line-numbered source inventory.

## Verification

Existing ARM64 Docker development container:
`clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.

- Pre-fix Release regression: **failed as expected** with actual `0` versus
  expected `CL_EMAXFILES=25`.
- Release `CK_RUN_SUITE=cl_suite CK_RUN_CASE=autoit_map T=1200`:
  **10/10 checks passed**.
- ASan/UBSan `CK_RUN_SUITE=cl_suite CK_RUN_CASE=autoit_map T=1200`:
  **10/10 checks passed**, with no sanitizer diagnostics.
- Both current `check_clamav` targets rebuilt successfully.
- `sh tools/largefile_source_guards.sh`: passed.
- `diff -u docs/largefile-inventory.tsv <(sh tools/largefile_inventory.sh)`:
  passed.
- `git diff --check`: passed.

## Identity and limitations

Starting repository commit: `8e837b88c89874b180a1a25f22d287f7d6be29db`.
The working tree is intentionally dirty and remains the source identity for
this receipt; no clean-commit claim is made. No commit or push was made.

Relevant current-source SHA-256 values:

- `libclamav/autoit.c`:
  `849d3a2feba040c9748d1feb81a0ef4d45f1c519d1c0340ffece824ef0d12561`
- `unit_tests/check_clamav.c`:
  `ea9ae124b0ae03aa2044e99055bee5917ddbb157ffdf03104de2dc8185f80138`
- generated `docs/largefile-inventory.tsv`:
  `408229cc4af6b0e293de38a9ca438f369bd6b9681cac5feae750bf9a7d6f685d`

This is ARM64 development evidence only. Certified Linux x86-64 execution,
exact/materialized 32-GiB evidence, production CVD/service and ingress,
resource/fanotify evidence, independent bytecode format-8 evidence, and final
release readiness remain open. No capability was promoted, and no commit or
push was made. No usage-reset or banked-reset credit was used.
