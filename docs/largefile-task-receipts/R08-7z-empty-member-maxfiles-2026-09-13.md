# Task receipt: R08 7-Zip empty-member MaxFiles accounting — 2026-09-13

Task ID / parent milestone: `R08` / `R00`

## Scope

Close the current-source 7-Zip path that extracted declared zero-byte logical
files without passing them through nested descriptor admission. Empty files
must consume inclusive `MaxFiles` while directories remain non-file entries.

Exact capability kind: `parser:CL_TYPE_7Z`.

## Implementation

- The zero-output 7-Zip member path now calls
  `cli_magic_scan_desc_type_reserved()` before temporary cleanup, matching the
  non-empty member path for child admission, `MaxFiles`, cache invalidation,
  and empty-file handling.
- Added a valid in-memory 7z archive with two `EmptyStream`/`EmptyFile`
  members. The regression covers `MaxFiles=2` rejection after the root and
  first child, plus exact `MaxFiles=3` completion.
- Added source guards and regenerated the line-numbered inventory.

## Verification

Existing ARM64 Docker development container:
`clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.

- Current Release `CK_RUN_SUITE=cl_suite CK_RUN_CASE=7z T=1200`:
  **1/1 CTest test passed**; the selected Check test executed **29/29** 7z
  cases.
- Current ASan/UBSan
  `ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1 UBSAN_OPTIONS=halt_on_error=1 CK_RUN_SUITE=cl_suite CK_RUN_CASE=7z T=1200`:
  **1/1 CTest test passed**; no sanitizer diagnostics were emitted.
- Both current `check_clamav` targets rebuilt successfully.
- `sh tools/largefile_source_guards.sh`: passed.
- Generated inventory refresh completed; freshness validation and
  `git diff --check` passed.

## Identity and limitations

The working tree is intentionally dirty and remains the source identity for
this receipt; no clean-commit claim is made. No commit or push was made.

Relevant current-source SHA-256 values:

- `libclamav/7z_iface.c`:
  `e60d4bc9ba4a07dc1116c5a1e5a19fceca9fc4ffc944d5dff9b772b34c06da7b`
- `unit_tests/check_clamav.c`:
  `5de5abf75c0ad2e3d89e1e0fc5b9f89b9b672124796c78a90bc4d505ac21cc11`
- `tools/largefile_source_guards.sh`:
  `46e929a7ef82fa2b0d47078003b6356feb06ee90e1b4fba99ef8b695a70b42d7`
- generated `docs/largefile-inventory.tsv`:
  `da722a96993ff5a7297b98452d1f97c9c9080f6306ec420e01e7d6046b6fb427`

This is ARM64 development evidence only. Certified Linux x86-64 execution,
exact/materialized 32-GiB evidence, production CVD/service and ingress,
resource/fanotify evidence, independent format-8 evidence, and final release
readiness remain open. No capability was promoted.
