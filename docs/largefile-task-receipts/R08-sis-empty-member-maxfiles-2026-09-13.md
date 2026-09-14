# Task receipt: R08 SIS empty-member MaxFiles accounting — 2026-09-13

Task ID / parent milestone: `R08` / `R00`

## Scope

Close the legacy Symbian SIS language-member path that skipped a declared
zero-byte variant before charging inclusive `MaxFiles`. An empty language
variant has no payload to materialize, but remains a logical child for nested
admission.

Exact capability kinds and IDs: `parser:CL_TYPE_SIS`,
`library:nested-scan-empty-completion`.

## Implementation

- SIS now routes each `lens[j] == 0` language variant through
  `cli_updatelimits(ctx, 0)` before continuing to the next variant.
- Limit failures are retained in the parser's existing `limit_status` result,
  and non-timeout failures mark the recognized layer incomplete so the empty
  child cannot produce a clean/cacheable result.
- Added a production-linked regression with one file represented by two empty
  language variants, covering `MaxFiles=2` rejection and exact `MaxFiles=3`
  completion. Added source guards and regenerated the line-numbered inventory.

## Verification

Existing ARM64 Docker development container:
`clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.

- Current Release `CK_RUN_SUITE=cl_suite CK_RUN_CASE=sis_member T=1200`:
  **1/1 CTest test passed**.
- Current ASan/UBSan `CK_RUN_SUITE=cl_suite CK_RUN_CASE=sis_member T=1200`:
  **1/1 CTest test passed**, with no sanitizer diagnostics.
- Both current `check_clamav` targets rebuilt successfully.
- `sh tools/largefile_source_guards.sh`: passed.
- Generated inventory refresh and freshness validation: passed.
- `git diff --check`: passed.

## Identity and limitations

The working tree is intentionally dirty and remains the source identity for
this receipt; no clean-commit claim is made. No commit or push was made.

Relevant current-source SHA-256 values:

- `libclamav/sis.c`:
  `8d7da94e5e11a3326712ccdafb1cfdf1a6647a8c14fe6ecff00b82f1cbe15abd`
- `unit_tests/check_clamav.c`:
  `525c97955cdde45d7d400a4080cd39e93faf57e45b668c0c7b5c5fca9acc0db8`
- `tools/largefile_source_guards.sh`:
  `498395c51f16efa4eaa6b43180f22cc8a2940161ab0847bbbbadb45149fcff1d`
- generated `docs/largefile-inventory.tsv`:
  `51e78e624a9115e2077f5c57483f087397770cb5cbf3280e333dba1578eccc93`

This is ARM64 development evidence only. Certified Linux x86-64 execution,
exact/materialized 32-GiB evidence, production CVD/service and ingress,
resource/fanotify evidence, independent format-8 evidence, and final release
readiness remain open. No capability was promoted.
