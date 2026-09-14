# Full `clamscan` integration — ASan/UBSan (2026-09-13)

## Scope

Run the complete registered `clamscan` integration target against the
current-source ARM64 `RelWithDebInfo` ASan/UBSan build. This extends the
focused R09 sanitizer evidence to the full application-facing test suite.

## Provenance

- source tree: `/src` mounted from the working tree;
- source manifest: 1,697 entries;
- source manifest SHA-256:
  `ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`;
- build directory: `/tmp/clamav-asan-current-20260912`;
- `clamscan` SHA-256:
  `1b9a4bfc0fd9eb99b1cbd84cadbf787e70bd89516f484bffa477efb0e40e7df2`;
- `CMakeCache.txt` SHA-256:
  `cfcb0fab0294875622cf295f6cb28f4ad95435e68015a86044e78540779dff50`;
- configuration: `RelWithDebInfo`, ASan/UBSan in C and C++, frame pointers
  retained, `ENABLE_APP=ON`, `ENABLE_MILTER=ON`, `ENABLE_TESTS=ON`,
  `ENABLE_UNRAR=ON`;
- incremental rebuild: exit 0, all targets reached 100%.

## Result

```text
ctest --test-dir /tmp/clamav-asan-current-20260912 -V -R '^clamscan$'
```

The target passed `1/1` in `183.77` seconds. Its underlying integration
harness ran 127 tests with zero failures and zero errors and one expected
platform skip: `Ran 127 tests in 183.463s`, `OK (skipped=1)`.

This includes the current parser/application corpus, R09 parser-policy and
ignored-type cases, fuzzy-image integration, corrected RAR/RAR-SFX backend
coverage, and the existing clean/detection/error behavior exercised by the
full `clamscan` suite. The captured output contained no
`AddressSanitizer`, `LeakSanitizer`, `UndefinedBehaviorSanitizer`, or
`runtime error:` diagnostics. Expected negative-test diagnostics, including
the PDF write-path error used by its test case, did not produce sanitizer
findings.

This is current-source ARM64 development evidence. It does not establish
certified x86-64, exact 32-GiB/materialized-resource, production CVD/service,
privileged fanotify, Sonic1, independent format-8, or final release
qualification.
