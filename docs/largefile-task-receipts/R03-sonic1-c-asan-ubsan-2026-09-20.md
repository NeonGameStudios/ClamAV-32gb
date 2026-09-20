# Task receipt: R03 Sonic1 C ASan/UBSan build and regression slice

Task ID / parent milestone: `R03` / `R12`

Scope: build the current Linux x86-64 candidate with GCC native AddressSanitizer
and UndefinedBehaviorSanitizer instrumentation, retain the Release feature
set, and run the non-exact CTest regression matrix.

Configuration:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`.
- Build directory: `/tmp/clamav-7f3458c4-asan-build`.
- Build type: `RelWithDebInfo`.
- Native flags: `-fsanitize=address,undefined -fno-omit-frame-pointer`.
- Required feature parity retained: tests, app, clamonacc, milter, UnRAR,
  shared/static libraries, large-file defaults, and exact qualification test.

Build and regression result:

```text
cmake --build /tmp/clamav-7f3458c4-asan-build --parallel 2
exit=0

ctest --test-dir /tmp/clamav-7f3458c4-asan-build \
  -E '^largefile_library_exact_32g$' --output-on-failure
31/31 tests passed
Total Test time (real) = 396.82 sec
exit=0
```

The exact 32-GiB test was excluded because this slice is sanitizer regression
evidence, not a substitute for the separately governed materialized exact-edge
qualification. No sanitizer diagnostics appeared in the CTest result.

Identities:

- Sanitizer `clamscan` SHA-256:
  `730b54206d3534c16c4edbd79637f3294cc0e4c73c455a705969aa76212db920`.
- CMake cache SHA-256:
  `3c648d81b4f2a29880faed802946452065185ae96c71a5a65ec8c41426be42b2`.
- Compile-commands SHA-256:
  `ad9577537148b36eed4def7bd46b1ef75d82f812779d3d4f5410f1da43abfba4`.
- Source manifest SHA-256:
  `1467bb29c64d76457408cecdefbc1ff9cb84aed64513a58eb76f00a919f16976`.

Rust status:

- Rust unit tests passed in the C-sanitized CTest run.
- Required Rust address instrumentation was not proven. Installed toolchains
  are `stable-x86_64-unknown-linux-gnu` and `1.97-x86_64-unknown-linux-gnu`.
- `rustc -Zsanitizer=address --version` failed with `-Z` accepted only on the
  nightly compiler. No toolchain was installed or downloaded.

State: `C-sanitizer-development-verified; Rust-sanitizer-and-release-evidence-open`
