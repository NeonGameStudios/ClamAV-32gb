# Task receipt: R08 HFS+ empty catalog-file MaxFiles accounting — 2026-09-13

Task ID / parent milestone: `R08` / `R00`

## Scope

Close the current-source HFS+ catalog path that recognized a regular file with
both data and resource forks empty but skipped it before shared child
admission. An empty regular catalog file is a logical child and must consume
the inclusive `MaxFiles` budget; directory records remain non-file entries.

Exact capability kind: `parser:CL_TYPE_PART_HFSPLUS`.

## Implementation

- `hfsplus_walk_catalog()` now routes a non-compressed regular file whose data
  and resource forks are both zero through `cli_updatelimits(ctx, 0)`.
- Configured limit failures remain fail-visible and preserve the canonical
  `Heuristics.Limits.Exceeded.MaxFiles` diagnostic and cache taint.
- Added a valid production-shaped HFS+ catalog fixture with an empty regular
  file. The regression checks rejection when the enclosing root already uses
  the only `MaxFiles` slot and clean completion when one child slot remains.
- Added source guards and refreshed the line-numbered inventory.

## Verification

Existing ARM64 Docker development container:
`clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.

- Current Release `CK_RUN_SUITE=cl_suite CK_RUN_CASE=hfs_map T=1200`:
  **1/1 CTest test passed**.
- Current ASan/UBSan
  `ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1 UBSAN_OPTIONS=halt_on_error=1 CK_RUN_SUITE=cl_suite CK_RUN_CASE=hfs_map T=1200`:
  **1/1 CTest test passed**; no sanitizer diagnostics were emitted.
- Both current `check_clamav` targets rebuilt successfully.
- `sh tools/largefile_source_guards.sh`: passed.
- Generated inventory freshness and `git diff --check`: passed.

## Identity and limitations

The working tree is intentionally dirty and remains the source identity for
this receipt; no clean-commit claim is made. No commit or push was made.

Relevant current-source SHA-256 values:

- `libclamav/hfsplus.c`:
  `5f9bb1563a03b08d3f2fbffdd4822f95f50571bac79c34366e3217ac993afb32`
- `unit_tests/check_clamav.c`:
  `c4be4de9901c67f176181a83fee96e728d44eef8b3569a7ec85286f1c98f26e5`
- `tools/largefile_source_guards.sh`:
  `147d191edb006b6ef7ec9433f45ecb9cac0dc21155a243a1724e372d2a50a831`
- generated `docs/largefile-inventory.tsv`:
  `8b29146929c1a27b08ddae6ab578308e4bf74037edb660a6db4bef857739865f`

This is ARM64 development evidence only. Certified Linux x86-64 execution,
exact/materialized 32-GiB evidence, production CVD/service and ingress,
resource/fanotify evidence, independent format-8 evidence, and final release
readiness remain open. No capability was promoted.
