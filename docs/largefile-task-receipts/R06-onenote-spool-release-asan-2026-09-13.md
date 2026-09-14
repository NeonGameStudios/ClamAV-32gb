# R06 OneNote spool-release sanitizer revalidation — 2026-09-13

Task ID / parent milestone: `R06` / `R03`.

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE`.

Source identity: branch `largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. The current-source manifest contains 1,697 entries
and has SHA-256
`c75877cc35ffc2d86a4a7c086cc2a51a80e026ec96a5e047ec223e98942246d9`.

Purpose: revalidate the R06 production-linked OneNote corpus case after adding
the post-scan temporary-ledger release assertion. The case uses the real
attachment-bearing `clam.exe.2010.one` corpus input, a bounded fmap callback,
a logical length of `256 MiB + 1`, and the independently expected nested
`OneNote.Reader.MZ` detection.

Environment and build:

- Existing Docker container `clamav-current-rust-build-20260911` was reused;
  no software was installed.
- The existing ARM64 `RelWithDebInfo` ASan/UBSan tree at
  `/tmp/clamav-asan-current-20260912` was reconfigured against the current
  checkout and rebuilt for `check_clamav`.
- CMake source-manifest SHA-256:
  `c75877cc35ffc2d86a4a7c086cc2a51a80e026ec96a5e047ec223e98942246d9`.
- CMake cache SHA-256:
  `284b963915e9b7878894e719b05658648d035a32519f802c643590002bc82f9c`.
- Focused `check_clamav` SHA-256:
  `3e5346b491693581b7a76ceaa6a4df8d0a32fde860802a80c9eea00074f46d3e`.

Verification:

- Command: `CK_RUN_SUITE=cl_suite CK_RUN_CASE=rust_onenote T=1200
  ./check_clamav` from the sanitizer `unit_tests` directory.
- Result: 4/4 checks passed with zero failures and zero errors, including the
  over-cap attachment detection and post-scan ledger-zero assertion.
- The retained test stderr contained no AddressSanitizer, LeakSanitizer,
  UndefinedBehaviorSanitizer, or runtime-error diagnostics.

Qualification boundary: this is current-source ARM64 Docker development
evidence only. It does not prove exact 32-GiB/materialized resources,
certified Linux x86-64 execution, production CVD or service behavior, Sonic1
execution, all late-offset OneNote variants, or final release qualification.
No capability was promoted.

State: `development-verified`.
