# Task receipt: R08 ALZ empty-member MaxFiles accounting — 2026-09-13

Task ID / parent milestone: `R08` / `R00`

## Scope

Close a zero-byte ALZ child path that bypassed inclusive `MaxFiles`
accounting. A valid stored ALZ member with zero compressed and uncompressed
bytes is still a logical nested child and must reach the scanner-facing
descriptor ingress, even though it has no payload bytes to match.

Exact capability kinds and IDs: `parser:CL_TYPE_ALZ`,
`library:nested-scan-empty-completion`.

## Observed defect

A valid 56-byte ALZ archive containing two empty stored members returned
`CL_SUCCESS` with `MaxFiles=2`. The root consumes one inclusive slot, so the
second child must fail with `CL_EMAXFILES` (`25`). The pre-fix production-linked
Release regression reproduced the false success (`0`).

## Implementation

- `cli_magic_scan_desc_type_internal()` now charges a zero-byte descriptor
  through `cli_updatelimits(ctx, 0)` before reconciling the owning layer's
  sticky status.
- The Rust ALZ scanner recognizes a valid empty stored member as a special
  zero-output case so it is not discarded by the exhausted extraction-size
  fast path.
- `AlzScanSink::finish()` now sends empty members through the scanner-facing
  spool handoff, allowing descriptor admission and `MaxFiles` accounting to
  run.
- Added the production-linked regression and source guards; regenerated the
  line-numbered source inventory.

## Verification

Existing ARM64 Docker development container:
`clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.

- Release `CK_RUN_SUITE=cl_suite CK_RUN_CASE=rust_alz`:
  **3/3 checks passed**.
- ASan/UBSan `CK_RUN_SUITE=cl_suite CK_RUN_CASE=rust_alz`:
  **2/2 checks passed**, with no sanitizer diagnostics.
- `sh tools/largefile_source_guards.sh`: passed.
- `diff -u docs/largefile-inventory.tsv <(sh tools/largefile_inventory.sh)`:
  passed.
- `git diff --check`: passed.
- A complete current-source Release CTest rerun was attempted after the
  change but was not counted: the container filesystem reached `No space left
  on device` during generated temporary scan-file creation. The resulting
  failures were environment/setup failures; the build completed successfully.
  Only the exact test-generated top-level `/tmp/clamav-*.tmp` files were
  removed afterward.

## Identity and limitations

Starting repository commit: `8e837b88c89874b180a1a25f22d287f7d6be29db`.
The working tree is intentionally dirty and remains the source identity for
this receipt; no clean-commit claim is made.

Relevant current-source SHA-256 values:

- `libclamav/scanners.c`:
  `fbf8c0cc4199ece87de0c0f0e700f2f4215cea24874f90526e2abb286ef43787`
- `libclamav_rust/src/alz.rs`:
  `2d157c111e8239078d4426db8a0c605d7e96887ef033350e1c432787abbbe86a`
- `libclamav_rust/src/scanners.rs`:
  `15adcc286a9b41edcd51c7f3726cc1fc5751ea30ba3a13456f07a5b8f9ab51c4`
- `unit_tests/check_clamav.c`:
  `b52e6b3276b2852dd209470728f64366a8ef13d37a36cc9358c352c07867e7d5`
- generated `docs/largefile-inventory.tsv`:
  `82559c3b95933959e701e8b294d7fbe6b6bb3f6a7f991768cf2cc769447a0a2f`

This is ARM64 development evidence only. Certified Linux x86-64 execution,
exact/materialized 32-GiB evidence, production CVD/service and ingress,
resource/fanotify evidence, independent bytecode format-8 evidence, and final
release readiness remain open. No capability was promoted, and no commit or
push was made. No usage-reset or banked-reset credit was used.
