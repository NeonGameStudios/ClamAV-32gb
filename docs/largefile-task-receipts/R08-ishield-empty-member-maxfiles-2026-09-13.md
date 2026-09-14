# Task receipt: R08 InstallShield empty-member MaxFiles accounting — 2026-09-13

Task ID / parent milestone: `R08` / `R00`

## Scope

Close the legacy InstallShield path that skipped declared zero-length embedded
files before charging inclusive `MaxFiles`. An empty embedded file has no
payload to materialize, but remains a logical child for nested admission.

Exact capability kinds and IDs: `parser:CL_TYPE_ISHIELD`,
`library:nested-scan-empty-completion`.

## Implementation

- `is_dump_and_scan()` now admits an empty embedded file through
  `cli_updatelimits(ctx, 0)` before returning.
- `is_parse_hdr()` now admits an empty CAB-backed file-table entry through the
  same logical-child boundary and keeps its per-container counter aligned.
- Configured-limit failures are returned immediately, and non-terminal limit
  failures mark the scan incomplete so they cannot become clean/cacheable.
- Added production-linked regressions covering two empty metadata records and
  two empty CAB-backed header records. The direct metadata case uses
  `MaxFiles=2`/`3`; the header case uses `MaxFiles=2`/`5` to include the outer
  `data1.hdr` and empty indexed-CAB support objects. Added source guards and
  regenerated the line-numbered source inventory.

## Verification

Existing ARM64 Docker development container:
`clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.

- Release `CK_RUN_SUITE=cl_suite CK_RUN_CASE=ishield_map T=1200`:
  **6/6 checks passed**.
- ASan/UBSan `CK_RUN_SUITE=cl_suite CK_RUN_CASE=ishield_map T=1200`:
  **6/6 checks passed**, with no sanitizer diagnostics.
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

- `libclamav/ishield.c`:
  `87939aa02d70c86738a04dfdadc236282fc198066b3f9f6e273e032eaa2b28bf`
- `unit_tests/check_clamav.c`:
  `dd73d437abf29fbb8685b84e3c9b2b50a05d70078fc25e903a39914928b34e5d`
- `tools/largefile_source_guards.sh`:
  `c3d41761dbfc184d7f42718be2631c5cc06420278f5b1a01132790bdc260f478`
- generated `docs/largefile-inventory.tsv`:
  `d8d388a1295c244a110be78651513ba6af3ca3729d4d4a80fd8851ce9e0a1bf9`

This is ARM64 development evidence only. Certified Linux x86-64 execution,
exact/materialized 32-GiB evidence, production CVD/service and ingress,
resource/fanotify evidence, independent bytecode format-8 evidence, and final
release readiness remain open. No capability was promoted, and no commit or
push was made. No usage-reset or banked-reset credit was used.
