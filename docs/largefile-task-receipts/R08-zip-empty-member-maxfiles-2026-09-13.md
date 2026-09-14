# Task receipt: R08 ZIP empty-member MaxFiles accounting — 2026-09-13

Task ID / parent milestone: `R08` / `R00`

## Scope

Close the ZIP catalogue path that skipped a valid member when both compressed
and uncompressed sizes were zero. An empty ZIP member has no payload to
materialize, but remains a logical child for inclusive `MaxFiles` admission.

Exact capability kinds and IDs: `parser:CL_TYPE_ZIP`,
`library:nested-scan-empty-completion`.

## Observed gap

The current `cli_unzip()` catalogue loop continued immediately for a
zero-size member, so it never reached nested admission or the shared
`scannedfiles` counter. This allowed empty members to bypass the root/child
file-count boundary.

## Implementation

- The empty-member branch now calls `cli_updatelimits(ctx, 0)` before
  continuing.
- A configured limit result is returned immediately; non-terminal limit
  failures mark the ZIP incomplete so the archive cannot normalize to a clean,
  cacheable result.
- Added a valid two-empty-member central-directory regression and a source
  guard; regenerated the line-numbered source inventory.

## Verification

Existing ARM64 Docker development container:
`clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.

- Release `CK_RUN_SUITE=cl_suite CK_RUN_CASE=zip T=1200`:
  **20/20 checks passed**.
- ASan/UBSan `CK_RUN_SUITE=cl_suite CK_RUN_CASE=zip T=1200`:
  **20/20 checks passed**, with no sanitizer diagnostics.
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
