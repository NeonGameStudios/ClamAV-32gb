# Large-file controls and Rust integration — ASan/UBSan (2026-09-13)

## Scope

Run the remaining bounded controls in the current-source ARM64
`RelWithDebInfo` ASan/UBSan build:

- on-access thread-pool lifecycle and configuration admission;
- clamd thread-pool admission and milter connection-pool controls;
- fail-closed proof-of-concept behavior;
- clamscan admission, clamd report protocol, and late ZIP-member detection;
- the complete registered `libclamav_rust` test target.

## Provenance

- source tree: `/src` mounted from the working tree;
- source manifest: 1,697 entries;
- source manifest SHA-256:
  `ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`;
- build directory: `/tmp/clamav-asan-current-20260912`;
- `check_onas_threadpool` SHA-256:
  `b572b71ce21cf246077e8143b5d5d330dcb0b84087525f57efccbc6c23aa6ae3`;
- `check_clamd_threadpool` SHA-256:
  `e3e918932d133ef6a7ae56fd7bc5945cb82eeace799480016271d289058a549a`;
- `check_milter_connpool` SHA-256:
  `d63b7e3c0e733b8c289651fd2fdd83d4207913a8e064467ade7e96415e2e2d35`;
- Rust test executable SHA-256:
  `bcf899e05e61f280ab00e08bb9c6485cc357db7d7b7fba3bd76f672b7133ca14`;
- `CMakeCache.txt` SHA-256:
  `cfcb0fab0294875622cf295f6cb28f4ad95435e68015a86044e78540779dff50`;
- configuration: `RelWithDebInfo`, ASan/UBSan in C and C++, frame pointers
  retained, `ENABLE_APP=ON`, `ENABLE_MILTER=ON`, `ENABLE_TESTS=ON`,
  `ENABLE_UNRAR=ON`.

## Result

```text
ctest --test-dir /tmp/clamav-asan-current-20260912 -V \
  -R '^(largefile_onaccess_threadpool|largefile_onaccess_config_admission|largefile_clamd_threadpool|largefile_milter_connpool|largefile_poc_fail_closed|largefile_clamscan_admission|largefile_clamd_report_protocol|largefile_zip_late_member|libclamav_rust)$'
```

All 9 targets passed in 11.36 seconds. The `libclamav_rust` target ran 159
tests with zero failures, zero ignored tests, and zero filtered tests. The
large-file controls passed their admission, lifecycle, fail-closed, report,
and late-member checks. The captured output contained no `AddressSanitizer`,
`LeakSanitizer`, `UndefinedBehaviorSanitizer`, or `runtime error:` diagnostics.

This is current-source ARM64 development evidence. It does not establish
certified x86-64, exact 32-GiB/materialized-resource, production CVD/service,
privileged fanotify, Sonic1, independent format-8, or final release
qualification.
