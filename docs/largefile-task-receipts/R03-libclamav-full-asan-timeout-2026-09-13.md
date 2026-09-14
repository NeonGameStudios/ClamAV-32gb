# Full `libclamav` sanitizer diagnostic — timeout boundary (2026-09-13)

## Scope

Attempt the complete current-source ARM64 `RelWithDebInfo` ASan/UBSan
`libclamav` integration target, then isolate whether the earlier failure was a
test duration boundary or an application assertion.

## Provenance

- source tree: `/src` mounted from the working tree;
- source manifest: 1,697 entries;
- source manifest SHA-256:
  `ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`;
- build directory: `/tmp/clamav-asan-current-20260912`;
- `check_clamav` SHA-256:
  `693452f4b76d8337803046131fd99b1e79f1d346ae0415d5b977a1b1ddbf1828`;
- `CMakeCache.txt` SHA-256:
  `cfcb0fab0294875622cf295f6cb28f4ad95435e68015a86044e78540779dff50`;
- configuration: `RelWithDebInfo`, C and C++ ASan/UBSan, frame pointers
  retained, `ENABLE_APP=ON`, `ENABLE_MILTER=ON`, `ENABLE_TESTS=ON`,
  `ENABLE_UNRAR=ON`.

## Authoritative CTest result

```text
ctest --test-dir /tmp/clamav-asan-current-20260912 -V -R '^libclamav$'
```

CTest failed `1/1` with exit 8 after `1,201.58` seconds. The underlying
`libclamav_test.py` invocation ran for `1,201.295` seconds and its
`check_clamav` process exited 111 because the configured
`CLAMAV_LIBCLAMAV_TEST_TIMEOUT=1200` was exceeded. The retained output had no
assertion failure or sanitizer diagnostic; the visible
`traverse_to: Failed open payload` line is the existing expected diagnostic
from the replaced-symlink test.

## Diagnostic follow-up

The same unfiltered `cl_suite` was then invoked directly with
`CK_RUN_SUITE=cl_suite`, `CK_FORK=yes`, and `T=1800`. `T` is a per-test-case
timeout rather than an aggregate timeout, so the coordinator stopped this
diagnostic-only process after approximately 30 minutes to avoid an
unbounded run. Before termination its retained Check log contained 1,328
`Passed` cases and 0 `Failed`/`Error` cases; no
`AddressSanitizer`, `LeakSanitizer`, `UndefinedBehaviorSanitizer`, or
`runtime error:` diagnostics were present. It is partial evidence, not a
passing full-suite result.

## Disposition

No production source change was made. The current ARM64 sanitizer build is
application-functional across the completed focused and frontend suites, but
the unfiltered core suite remains unverified within the configured local
duration. The next valid step is a certified runner with the roadmap's full
R03 resource/time profile, or a deliberately scoped suite decomposition that
retains the complete case list and final verifier. Do not call this a
qualification pass.

State: `development-verified; aggregate sanitizer suite timeout`
