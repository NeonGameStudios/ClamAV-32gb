# Task receipt: R06/R08 current-source document and mail ASan/UBSan slices

Task IDs / parent milestones: `R06`, `R08` / `R03`

The current ARM64 `RelWithDebInfo` ASan/UBSan build at
`/tmp/clamav-asan-current-20260912` was run against the source-mounted
repository with source manifest SHA-256
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`.
The Check runner used `CVD_CERTS_DIR=/src/unit_tests/input/signing/verify`,
`CK_FORK=yes`, `CK_DEFAULT_TIMEOUT=300`, and `T=60`.

The following slices completed successfully:

- TNEF: `tnef` 18/18, `tnef_map` 3/3, `tnef_debug` 2/2
- HWP/HWPML: `hwp3_api` 1/1, `hwp3_corpus` 1/1, `hwpml` 2/2,
  `hwpml_map` 4/4, `hwpml_corpus` 1/1
- RIFF: `riff` 9/9, `riff_corpus` 1/1, `riff_map` 1/1
- Mail: `mail` 16/16

Total: 59 checks, 0 failures, 0 errors. The runner output contained no ASan,
UBSan, LeakSanitizer, or runtime-error diagnostics.

This is ARM64 development evidence only. These slices do not supply the
roadmap's capability-specific acceptance records, full-size/materialized
fixtures, production CVD/service, certified Linux x86-64, resource/fanotify,
independent format-8, Sonic1, or final release evidence. No capability was
promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
