# R03 application-facing ASan/UBSan CTest revalidation (2026-09-13)

## Scope

Revalidate the current-source application-facing targets after the latest
source-manifest rebinding. The selected CTest group excludes the separately
recorded `libclamav` and Rust suites and covers large-file controls, service
and acceptance verifiers, CLI ingress, daemon behavior, milter protocol and
quota behavior, queue/on-access controls, `clamscan`, `clamd`, `freshclam`,
and `sigtool`.

## Provenance

- source tree: `/src` mounted from the current working tree;
- source manifest: 1,697 entries;
- source manifest SHA-256:
  `1664c22ff783fd269c2c0e12e21ba81e05ce6c603fff66fe8a0530d68b87093d`;
- build directory: `/tmp/clamav-asan-current-20260912`;
- `CMakeCache.txt` SHA-256:
  `781535cdabf73f6797c705aebd98b706e1771be5a8dc72db7a7985f67b09e5cd`;
- `unit_tests/check_clamav` SHA-256:
  `3e5346b491693581b7a76ceaa6a4df8d0a32fde860802a80c9eea00074f46d3`;
- configuration: `RelWithDebInfo` with AddressSanitizer and UndefinedBehaviorSanitizer,
  frame pointers retained, `ENABLE_APP=ON`, `ENABLE_MILTER=ON`,
  `ENABLE_TESTS=ON`, and `ENABLE_UNRAR=ON`.

## Result

The following command completed with exit 0:

```text
T=1200 ctest --output-on-failure \
  -R '^(largefile_|clamav_milter_|clamd$|clamscan$|freshclam$|sigtool$)'
```

All 26 selected targets passed in 515.72 seconds. This included 21
`largefile`/release-control targets, both milter targets, `clamscan` in
188.84 seconds, `clamd` in 234.64 seconds, `freshclam`, and `sigtool`.
The retained CTest and unit-test logs contain no `AddressSanitizer`,
`LeakSanitizer`, `UndefinedBehaviorSanitizer`, or `runtime error:`
diagnostics.

This is ARM64 development evidence only. It does not establish certified
x86-64, full-size/materialized edge, production CVD/service, resource,
privileged fanotify, Sonic1, independent format-8 bytecode, or final release
qualification. No capability status was promoted.
