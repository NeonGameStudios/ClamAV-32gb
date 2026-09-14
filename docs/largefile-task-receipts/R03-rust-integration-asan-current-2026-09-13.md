# R03 current-source Rust integration ASan/UBSan revalidation (2026-09-13)

## Scope

Run the standalone Rust integration target against the current-source
sanitizer build. This covers the reader-backed FMap bridge, fuzzy-image FFI,
modern and legacy OneNote paths, Rust scanner status propagation, spool
cleanup, and bounded archive/parser helpers.

## Provenance

- source tree: `/src` mounted from the current working tree;
- source manifest: 1,697 entries;
- source manifest SHA-256:
  `1664c22ff783fd269c2c0e12e21ba81e05ce6c603fff66fe8a0530d68b87093d`;
- build directory: `/tmp/clamav-asan-current-20260912`;
- `CMakeCache.txt` SHA-256:
  `781535cdabf73f6797c705aebd98b706e1771be5a8dc72db7a7985f67b09e5cd`;
- Rust/C integration target: CTest `libclamav_rust`;
- configuration: `RelWithDebInfo` with AddressSanitizer and UndefinedBehaviorSanitizer,
  frame pointers retained.

## Result

The following target completed with exit 0 in 2.44 seconds:

```text
ctest --output-on-failure -R '^libclamav_rust$'
```

The retained Rust test output reports:

```text
test result: ok. 159 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The retained CTest and Rust logs contain no `AddressSanitizer`,
`LeakSanitizer`, `UndefinedBehaviorSanitizer`, or `runtime error:`
diagnostics. Compiler deprecation warnings remain non-fatal and are unrelated
to this roadmap slice.

This is ARM64 development evidence only. It does not establish certified
x86-64, full-size/materialized edge, production CVD/service, resource,
privileged fanotify, Sonic1, independent format-8 bytecode, or final release
qualification. No capability status was promoted.
