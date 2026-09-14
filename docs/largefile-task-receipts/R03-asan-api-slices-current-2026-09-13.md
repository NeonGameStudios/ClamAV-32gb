# Task receipt: R03 current-source API ASan/UBSan slices

Task ID / parent milestone: `R03`

The current ARM64 `RelWithDebInfo` ASan/UBSan build at
`/tmp/clamav-asan-current-20260912` was run against the source-mounted
repository with source manifest SHA-256
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`.
The Check runner used the repository signing-certificate directory through
`CVD_CERTS_DIR=/src/unit_tests/input/signing/verify`.

Substantive API slices completed with the following results:

- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_callback_api T=60`: 4 checks,
  0 failures, 0 errors.
- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_scan_api T=60`: 836 checks,
  0 failures, 0 errors.

The runner output contained no ASan, UBSan, LeakSanitizer, or runtime-error
diagnostics. A `cl_load` invocation was also exercised but selected no checks;
it is not counted as coverage.

This is ARM64 development evidence only. The aggregate `libclamav` sanitizer
target remains separately unresolved at its 1,200-second CTest budget;
certified Linux x86-64, exact 32-GiB/materialized edges, production
CVD/service, privileged fanotify, Sonic1, independent format-8, and final
release evidence remain open. No capability was promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
