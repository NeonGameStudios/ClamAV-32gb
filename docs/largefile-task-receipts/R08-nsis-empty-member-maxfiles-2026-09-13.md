# Task receipt: R08 NSIS empty-member MaxFiles accounting — 2026-09-13

Task ID / parent milestone: `R08` / `R00`

## Scope

Close the NSIS paths that skipped declared zero-byte members before charging
inclusive `MaxFiles`. An empty NSIS member has no payload to materialize, but
remains a logical child for nested admission. The four-byte archive CRC trailer
must remain outside the member count.

Exact capability kinds and IDs: `parser:CL_TYPE_NULSFT`,
`library:nested-scan-empty-completion`.

## Implementation

- Non-solid NSIS members now decrement the remaining member-table extent and
  admit zero-byte children through `cli_updatelimits(ctx, 0)`.
- The solid path now decodes a member-size header before applying the
  size-based byte limit, so a decoded zero-byte child is admitted through the
  same logical-child boundary.
- The pre-dispatch zero-size `cli_checklimits()` was removed after the parser
  distinguished a real member from the archive CRC probe; this allows an exact
  root-plus-children budget to complete without charging the trailer.
- Configured-limit failures remain fail-visible and non-cacheable.
- Added a production-linked regression with two zero-byte non-solid members,
  covering `MaxFiles=2` rejection and exact `MaxFiles=3` completion. A
  synthetic solid stream was not retained because it was incompatible with
  the bundled NSIS decoder and would not be trustworthy evidence.

## Verification

Existing ARM64 Docker development container:
`clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.

- Current Release `CK_RUN_SUITE=cl_suite CK_RUN_CASE=nulsft T=1200`:
  **1/1 CTest test passed**.
- Current ASan/UBSan `CK_RUN_SUITE=cl_suite CK_RUN_CASE=nulsft T=1200`:
  **1/1 CTest test passed**, with no sanitizer diagnostics.
- Both current `check_clamav` targets rebuilt successfully.
- `sh tools/largefile_source_guards.sh`: passed.
- Generated inventory refresh and freshness validation: passed.
- `git diff --check`: passed.

## Identity and limitations

The working tree is intentionally dirty and remains the source identity for
this receipt; no clean-commit claim is made. No commit or push was made.

Relevant current-source SHA-256 values:

- `libclamav/nsis/nulsft.c`:
  `3498b6224a8ebf02131613394c9d974c6efcfead7d68b704d04e9b32ae888892`
- `unit_tests/check_clamav.c`:
  `4d7ff0c77275642eabdd87b971bdabdd026890d8a26adee57dd4e175af82ed5c`
- `tools/largefile_source_guards.sh`:
  `45f7c561c5a0635f25ccdb792c06fc30f4c55e66c46a8e8d41f7f1ba4c237855`
- generated `docs/largefile-inventory.tsv`:
  `6b2dcd0ac1a0159de0388f0c8133927e4550a51fc1ce604e7a6bda799130bfdf`

This is ARM64 development evidence only. Certified Linux x86-64 execution,
exact/materialized 32-GiB evidence, production CVD/service and ingress,
resource/fanotify evidence, independent format-8 evidence, and final release
readiness remain open. No capability was promoted.
