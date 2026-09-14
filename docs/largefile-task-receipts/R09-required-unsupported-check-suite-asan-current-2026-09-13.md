# R09 required-unsupported Check suite — current-source ASan/UBSan (2026-09-13)

## Scope

Re-run the complete `required_unsupported` Check case group against the
current-source ARM64 `RelWithDebInfo` sanitizer build. This is the C-level
development coverage for the seven R09 rows that remain in scope: RAR,
RAR-SFX, ignored classifier types, compiled Python, AI-model parsing, and
fuzzy-image admission/matching controls.

## Provenance

- source tree: `/src` mounted from the current working tree;
- source manifest: 1,697 entries;
- source manifest SHA-256:
  `1664c22ff783fd269c2c0e12e21ba81e05ce6c603fff66fe8a0530d68b87093d`;
- build directory: `/tmp/clamav-asan-current-20260912`;
- `unit_tests/check_clamav` SHA-256:
  `3e5346b491693581b7a76ceaa6a4df8d0a32fde860802a80c9eea00074f46d3`;
- `CMakeCache.txt` SHA-256:
  `781535cdabf73f6797c705aebd98b706e1771be5a8dc72db7a7985f67b09e5cd`;
- configuration: `RelWithDebInfo` with AddressSanitizer and UndefinedBehaviorSanitizer,
  frame pointers retained, `ENABLE_APP=ON`, `ENABLE_MILTER=ON`,
  `ENABLE_TESTS=ON`, and `ENABLE_UNRAR=ON`;
- test log: `/tmp/clamav-asan-current-20260912/unit_tests/test.log`;
- sanitizer stderr: `/tmp/clamav-asan-current-20260912/unit_tests/test-stderr.log`.

## Result

The following current-source command completed successfully:

```text
CK_RUN_SUITE=cl_suite CK_RUN_CASE=required_unsupported T=1200 \
  ./unit_tests/check_clamav
```

The retained Check log reports:

```text
Results for all suites run:
100%: Checks: 57, Failures: 0, Errors: 0
```

The run covered the RAR/RAR-SFX unavailable-backend controls, ignored-type
raw-matching and incomplete-result behavior, compiled-Python structural and
marshal-reference cases, ONNX/GGUF/TFLite structural and boundary cases, and
raw-matching precedence. A scan of the retained stderr found no
`AddressSanitizer`, `LeakSanitizer`, `UndefinedBehaviorSanitizer`, or
`runtime error:` diagnostics.

This is ARM64 development evidence only. It does not establish certified
x86-64, full-size/materialized edge, production CVD/service, resource,
privileged fanotify, Sonic1, independent format-8 bytecode, or final release
qualification. No capability status was promoted.
