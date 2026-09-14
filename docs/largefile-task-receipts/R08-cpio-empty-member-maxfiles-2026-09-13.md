# Task receipt: R08 CPIO empty-member MaxFiles accounting — 2026-09-13

Task ID / parent milestone: `R08` / `R00`

## Scope

Close the CPIO old, ODC, newc, and CRC paths that skipped ordinary
zero-length members without charging inclusive `MaxFiles`. The `TRAILER!!!`
record remains a non-child terminator and must not consume a slot.

Exact capability kinds and IDs: `parser:CL_TYPE_CPIO_OLD`,
`parser:CL_TYPE_CPIO_ODC`, `parser:CL_TYPE_CPIO_NEWC`,
`parser:CL_TYPE_CPIO_CRC`, `library:nested-scan-empty-completion`.

## Implementation

- Added a shared `cpio_admit_empty_member()` boundary that charges each
  ordinary empty member through `cli_updatelimits(ctx, 0)`.
- Preserved trailer recognition before admission, so a complete archive can
  still finish when the two ordinary empty members exactly reach `MaxFiles`.
- Configured-limit failures are returned and marked incomplete, preventing a
  false clean/cacheable result.
- Added a production-linked regression covering MaxFiles=2 rejection and
  MaxFiles=3 completion for all four CPIO formats; added source guards and
  regenerated the line-numbered source inventory.

## Verification

Existing ARM64 Docker development container:
`clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.

- Release `CK_RUN_SUITE=cl_suite CK_RUN_CASE=cpio T=1200`:
  **3/3 checks passed**.
- ASan/UBSan `CK_RUN_SUITE=cl_suite CK_RUN_CASE=cpio T=1200`:
  **2/2 checks passed** with `ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1`;
  no ASan/UBSan diagnostics were emitted. A prior sanitizer invocation was
  killed by the container runtime with exit 137 and produced no test result;
  it is not counted as evidence.
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

- `libclamav/cpio.c`:
  `afe4c0716c8fbfd1fa617ccd6e2361b4412de8e571310f4c5f90d84deeadb7f2`
- `unit_tests/check_clamav.c`:
  `f7e5e63f8c9388c8001fb20ecb240af71723510c6edb1f84deb92701654bc40b`
- `tools/largefile_source_guards.sh`:
  `0ccec35504e2812b4538da244f0cbd2cf4ba97ed755e5a8e5a5e24b14e1b4d39`
- generated `docs/largefile-inventory.tsv`:
  `c1f7c5787e086621ccf401a78ea66b299e5dc361ab5c1d5a5a58732dce4dcc6e`

This is ARM64 development evidence only. Certified Linux x86-64 execution,
exact/materialized 32-GiB evidence, production CVD/service and ingress,
resource/fanotify evidence, independent bytecode format-8 evidence, and final
release readiness remain open. No capability was promoted, and no commit or
push was made. No usage-reset or banked-reset credit was used.
