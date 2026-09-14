# Task receipt: R03 current-source `cl_api` ASan/UBSan slice

Task ID / parent milestone: `R03`

The current ARM64 `RelWithDebInfo` ASan/UBSan build at
`/tmp/clamav-asan-current-20260912` was run against the source-mounted
repository with source manifest SHA-256
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`.

The Check test runner was invoked with the certificate directory explicitly
bound to the mounted source tree:

```text
CVD_CERTS_DIR=/src/unit_tests/input/signing/verify
CK_FORK=yes CK_DEFAULT_TIMEOUT=300
CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_api T=60 ./check_clamav
```

Result: `Checks: 528, Failures: 0, Errors: 0`.

The retained run produced no ASan, UBSan, LeakSanitizer, or runtime-error
diagnostics. This is ARM64 development evidence only. The aggregate
`libclamav` sanitizer target remains separately unresolved at its 1,200-second
CTest budget; this slice does not turn that timeout into a full-suite pass.
Certified Linux x86-64, exact 32-GiB/materialized edges, production
CVD/service, privileged fanotify, Sonic1, independent format-8, and final
release evidence remain open. No capability was promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
