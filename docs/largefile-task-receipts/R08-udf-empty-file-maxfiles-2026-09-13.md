# Task receipt: R08 UDF empty-file MaxFiles accounting — 2026-09-13

Task ID / parent milestone: `R08` / `R00`

## Scope

Close the current-source UDF path that returned a valid regular file with no
allocation descriptors, or only zero-length extents, without passing it
through nested child admission. Empty UDF files remain logical children and
must consume inclusive `MaxFiles`.

Exact capability kind: `parser:CL_TYPE_UDF`.

## Implementation

- Added `udf_admit_empty_file()` and route both zero-descriptor and zero-total-
  length regular-file paths through `cli_updatelimits(ctx, 0)`.
- Configured limit failures remain fail-visible and preserve the canonical
  `Heuristics.Limits.Exceeded.MaxFiles` diagnostic and cache taint.
- Extended the valid anchored UDF corpus regression with an empty regular
  child, covering rejection when the enclosing root already uses the only
  `MaxFiles` slot and clean completion when one child slot remains.
- Refreshed the line-numbered inventory.

## Verification

Existing ARM64 Docker development container:
`clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.

- Current Release `CK_RUN_SUITE=cl_suite CK_RUN_CASE=udf_corpus T=1200`:
  **1/1 CTest test passed**.
- Current ASan/UBSan
  `ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1 UBSAN_OPTIONS=halt_on_error=1 CK_RUN_SUITE=cl_suite CK_RUN_CASE=udf_corpus T=1200`:
  **1/1 CTest test passed**; no sanitizer diagnostics were emitted.
- Both current `check_clamav` targets rebuilt successfully.
- `sh tools/largefile_source_guards.sh`: passed.
- Generated inventory freshness and `git diff --check`: passed.

## Identity and limitations

The working tree is intentionally dirty and remains the source identity for
this receipt; no clean-commit claim is made. No commit or push was made.

Relevant current-source SHA-256 values:

- `libclamav/udf.c`:
  `434561e7ef8f8f87d080bc4eafa836f4b149b6e12dbd1759d51bd3b0ecade71d`
- `unit_tests/check_clamav.c`:
  `7429a2f93b67a1842d75dbd751018cb1f9c5fb45666995e98480ff80955ca2e0`
- `tools/largefile_source_guards.sh`:
  `147d191edb006b6ef7ec9433f45ecb9cac0dc21155a243a1724e372d2a50a831`
- generated `docs/largefile-inventory.tsv`:
  `ff99a8a87363696dfa3fc1e6281928c5ef3bf12b85a9b998e0dfb21e6df83b3e`

This is ARM64 development evidence only. Certified Linux x86-64 execution,
exact/materialized 32-GiB evidence, production CVD/service and ingress,
resource/fanotify evidence, independent format-8 evidence, and final release
readiness remain open. No capability was promoted.
