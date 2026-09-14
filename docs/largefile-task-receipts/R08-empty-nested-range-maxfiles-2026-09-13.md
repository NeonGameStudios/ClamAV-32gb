# Task receipt: R08 empty nested-range MaxFiles accounting — 2026-09-13

Task ID / parent milestone: `R08` / `R00`

## Scope

Close the shared nested-fmap path that returned a zero-byte nested range as a
clean no-match without consuming a logical-child `MaxFiles` slot. This is
exercised by a valid HWPOLE2 wrapper whose four-byte size prefix describes an
empty payload.

Exact capability kind: `parser:CL_TYPE_HWPOLE2`.

## Implementation

- `cli_magic_scan_nested_fmap_type()` now routes a zero-byte nested range
  through `cli_updatelimits(ctx, 0)` before reconciling the clean result.
- Added a focused HWPOLE2 regression covering rejection when the enclosing
  wrapper already uses the only `MaxFiles` slot and exact completion when one
  child slot remains.
- Updated the source guard for the new assignment-and-reconcile control flow
  and refreshed the line-numbered inventory.

## Verification

Existing ARM64 Docker development container:
`clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.

- Current Release `CK_RUN_SUITE=cl_suite CK_RUN_CASE=hwpole2_map T=1200`:
  **1/1 CTest test passed**.
- Current ASan/UBSan
  `ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1 UBSAN_OPTIONS=halt_on_error=1 CK_RUN_SUITE=cl_suite CK_RUN_CASE=hwpole2_map T=1200`:
  **1/1 CTest test passed**; no sanitizer diagnostics were emitted.
- Both current `check_clamav` targets rebuilt successfully. The Release build
  retained one pre-existing `scanners.c` maybe-uninitialized warning in the
  TFLite helper; it was unrelated to this change.
- `sh tools/largefile_source_guards.sh`: passed.
- Generated inventory freshness and `git diff --check`: passed.

## Identity and limitations

The working tree is intentionally dirty and remains the source identity for
this receipt; no clean-commit claim is made. No commit or push was made.

Relevant current-source SHA-256 values:

- `libclamav/scanners.c`:
  `18f77cebab01916ca35a8e7942b0ac89eaccedf997b97422e6a59d09e303f2a4`
- `unit_tests/check_clamav.c`:
  `060db26d4d62cf8aeb4008acda4e96f72d1125eddffc5d033fa59cb77f99ed7b`
- `tools/largefile_source_guards.sh`:
  `153b3b41db76c92462d93a7a8980d400f838cf9286e3f2955d3e4ff5a77dddce`
- generated `docs/largefile-inventory.tsv`:
  `539dd504874565f11ec7fdc970e94fae532ec1c7b55d524dbb0bb02dfa625c5f`

This is ARM64 development evidence only. Certified Linux x86-64 execution,
exact/materialized 32-GiB evidence, production CVD/service and ingress,
resource/fanotify evidence, independent format-8 evidence, and final release
readiness remain open. No capability was promoted.
