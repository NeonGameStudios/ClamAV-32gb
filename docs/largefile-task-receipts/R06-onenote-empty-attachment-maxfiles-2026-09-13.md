# Task receipt: R06 legacy OneNote empty-attachment MaxFiles accounting — 2026-09-13

Task ID / parent milestone: `R06` / `R00`

## Scope

Close the legacy OneNote scanner's zero-byte attachment path. A legacy
attachment record with a declared length of zero is still a logical nested
child and must pass through descriptor admission so inclusive `MaxFiles`
accounting and sticky completion status remain observable.

Exact capability kinds and IDs: `parser:CL_TYPE_ONENOTE`,
`library:nested-scan-empty-completion`.

## Observed defect

A valid legacy OneNote marker followed by two zero-length attachment records
returned `CL_SUCCESS` with `MaxFiles=2`. The root consumes one inclusive slot,
so the second child must fail with `CL_EMAXFILES` (`25`). The pre-fix
production-linked Release regression reproduced the false success (`0`).

## Implementation

- `OneNoteScanSink::finish()` now sends empty legacy attachment spools through
  `TempSpool::scan()` instead of treating them as an unscanned clean result.
- The existing scanner descriptor ingress charges the zero-byte child through
  `cli_updatelimits(ctx, 0)` and preserves any owning-layer incomplete state.
- Added a production-linked regression and a source guard; regenerated the
  line-numbered source inventory.

## Verification

Existing ARM64 Docker development container:
`clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.

- Pre-fix Release regression: **failed as expected** with actual `0` versus
  expected `CL_EMAXFILES=25`.
- Release `CK_RUN_SUITE=cl_suite CK_RUN_CASE=rust_onenote T=1200`:
  **5/5 checks passed**.
- ASan/UBSan `CK_RUN_SUITE=cl_suite CK_RUN_CASE=rust_onenote T=1200`:
  **5/5 checks passed**, with no sanitizer diagnostics.
- Both current `check_clamav` targets rebuilt successfully.
- `sh tools/largefile_source_guards.sh`: passed.
- `diff -u docs/largefile-inventory.tsv <(sh tools/largefile_inventory.sh)`:
  passed.
- `git diff --check`: passed.

## Identity and limitations

Starting repository commit: `8e837b88c89874b180a1a25f22d287f7d6be29db`.
The working tree is intentionally dirty and remains the source identity for
this receipt; no clean-commit claim is made. No commit or push was made.

This is ARM64 development evidence only. Certified Linux x86-64 execution,
exact/materialized 32-GiB evidence, production CVD/service and ingress,
resource/fanotify evidence, independent bytecode format-8 evidence, and final
release readiness remain open. No capability was promoted, and no usage-reset
or banked-reset credit was used.
