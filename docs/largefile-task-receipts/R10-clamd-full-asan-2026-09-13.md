# Full `clamd` integration — ASan/UBSan (2026-09-13)

## Scope

Run the complete registered `clamd` integration target against the
current-source ARM64 `RelWithDebInfo` ASan/UBSan build. This complements the
dedicated development service capture with the daemon's full integration
suite.

## Provenance

- source tree: `/src` mounted from the working tree;
- source manifest: 1,697 entries;
- source manifest SHA-256:
  `ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`;
- build directory: `/tmp/clamav-asan-current-20260912`;
- `clamd` SHA-256:
  `3c56e8cdd78105fa4df5694b938c1099831ccf193bec28e6d89f3d120a69d8b9`;
- `CMakeCache.txt` SHA-256:
  `cfcb0fab0294875622cf295f6cb28f4ad95435e68015a86044e78540779dff50`;
- configuration: `RelWithDebInfo`, ASan/UBSan in C and C++, frame pointers
  retained, `ENABLE_APP=ON`, `ENABLE_MILTER=ON`, `ENABLE_TESTS=ON`,
  `ENABLE_UNRAR=ON`.

## Result

```text
ctest --test-dir /tmp/clamav-asan-current-20260912 -V -R '^clamd$'
```

The target passed `1/1` in `233.35` seconds. Its integration harness ran 18
tests with zero failures and zero errors: `Ran 18 tests in 233.084s`, `OK`.
The run exercised daemon startup/health, scan and reload behavior, report and
stream paths, limit outcomes, clamdscan modes, and the `ReadTimeout=0`
structured-stream case. The captured output contained no `AddressSanitizer`,
`LeakSanitizer`, `UndefinedBehaviorSanitizer`, or `runtime error:` diagnostics.

This is current-source ARM64 development evidence. It does not establish
certified x86-64, exact 32-GiB/materialized-resource, production CVD/service,
privileged fanotify, Sonic1, independent format-8, or final release
qualification.
