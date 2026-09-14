# Task receipt: R06 OneNote reader-backed spool release

Task ID / parent milestone: `R06` / reader-backed modern OneNote

Exact capability kind:id list: `feature:onenote-modern-over-256m`; no
capability status change.

Canonical checkout and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- starting commit: `8e837b88c89874b180a1a25f22d287f7d6be29db`
- working tree intentionally remains dirty; existing changes were preserved

## Observed gap and expected behavior

The existing production-linked reader-backed OneNote test proved successful
nested detection above the former 256-MiB whole-input cap, but did not assert
that parser-owned object-data spools and nested attachment spools release their
shared temporary reservations before the scan returns. R06 requires successful
reader-backed extraction to leave no temporary reservation charged.

## Changes made

`unit_tests/check_clamav.c` now asserts, in the real corpus-backed
`rust_onenote` over-cap detection case, that `ctx.temporary_bytes` is zero on
successful return and that `ctx.temporary_peak` was nonzero. This binds the
cleanup check to the production `scan_onenote()` path, its parser
`BlobSpoolBudget`, and the nested `TempSpool` attachment handoff.

## Verification

- Existing Docker toolchain, current source mounted at `/src`:
  `cmake --build /tmp/clamav-release-current-20260913 --target check_clamav -j1`
  — **exit 0**.
- Focused current-source test:
  `CK_RUN_SUITE=cl_suite CK_RUN_CASE=rust_onenote T=900 unit_tests/check_clamav`
  — **exit 0**, 4 checks, 0 failures, 0 errors.
- Current source manifest: 1,697 entries; SHA-256
  `049e3c72c8ce0a17d10b350be19c4dc74d0d13a3bb904b9ce1e92f9ff45995c9`.
- Rebuilt `check_clamav` SHA-256:
  `395d236f58f664a2cd8bbe8718e3e1e14fc4c563d2764024ae32f75c0581f067`.
- Release build `CMakeCache.txt` SHA-256:
  `2010829dbb1fb883a2c22acb4462931e47cedd280db994e6f497ce9040d5bff7`.
- `git diff --check -- unit_tests/check_clamav.c` — **passed**.

This is ARM64 development evidence only. Certified Linux x86-64, fully
materialized large-file edges, sanitizer coverage for this newly tightened
case, production CVD/service evidence, Sonic1, resource/fanotify evidence,
and final R12–R15 qualification remain open. No capability was promoted.

No local software installation, usage reset, GitHub workflow action, commit,
or push was used.

State: `development-verified`
