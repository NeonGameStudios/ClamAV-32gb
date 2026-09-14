# Task receipt: R08/R09 current-source broad ASan/UBSan suite slices

Task IDs / parent milestones: `R08`, `R09` / `R03`

The current ARM64 `RelWithDebInfo` ASan/UBSan build at
`/tmp/clamav-asan-current-20260912` was run against the source-mounted
repository with source manifest SHA-256
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`.
The Check runner used `CVD_CERTS_DIR=/src/unit_tests/input/signing/verify`,
`CK_FORK=yes`, `CK_DEFAULT_TIMEOUT=300`, and `T=60`.

The following broad suites completed successfully:

- `mspack`: 8/8
- `ole2`: 24/24
- `pe`: 16/16
- `parser_regressions`: 4/4
- `required_unsupported`: 57/57

Total: 109 checks, 0 failures, 0 errors. The runner output contained no ASan,
UBSan, LeakSanitizer, or runtime-error diagnostics.

This is ARM64 development evidence only. The complete aggregate `libclamav`
sanitizer target remains separately unresolved at its 1,200-second CTest
budget; these slices do not convert that timeout into a full-suite pass. They
also do not supply the roadmap's capability-specific acceptance records,
full-size/materialized fixtures, production CVD/service, certified Linux
x86-64, resource/fanotify, independent format-8, Sonic1, or final release
evidence. No capability was promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
