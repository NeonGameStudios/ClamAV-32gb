# R03 aggregate ASan/UBSan timeout receipt — 2026-09-13

## Scope

Re-run the repository's aggregate `libclamav` C suite against the current
source after the R04 verifier hardening changes.

## Exact inputs

- Source manifest: `4ff6260cf89396c0d4a5c96c889b89558cab599e33c4b26976921ce629749efc`
- Build: `/tmp/clamav-asan-current-20260912`
- Host: disposable `rust:1.97-bookworm` ARM64 container
- Binary: `/tmp/clamav-asan-current-20260912/unit_tests/check_clamav`
- C test-case timeout: `T=2400`
- Python aggregate timeout: `CLAMAV_LIBCLAMAV_TEST_TIMEOUT=2700`

## Commands and outcome

The configured CTest target first stopped at 1,201 seconds because the
generated ASan CTest environment sets `CLAMAV_LIBCLAMAV_TEST_TIMEOUT=1200`.
The same `libclamav_test.py` invocation was then run directly from
`/src/unit_tests` with the generated environment reproduced and both timeout
layers explicitly extended.

The direct run reached the Python 2,700-second limit while still executing
`cl_scan_api` callback cases:

```text
Using test case timeout of 2400 seconds set by user
Execution timeout exceeded for ... check_clamav ... command.
Ran 1 test in 2700.418s
FAILED (failures=1)
```

This is incomplete ARM64 sanitizer evidence, not a pass or a capability
promotion. The captured stderr contains no `AddressSanitizer`,
`UndefinedBehaviorSanitizer`, `runtime error`, or sanitizer-summary diagnostic.
The limiting condition is aggregate-suite duration on this development host;
certified Linux x86-64 aggregate evidence remains required by the roadmap.
