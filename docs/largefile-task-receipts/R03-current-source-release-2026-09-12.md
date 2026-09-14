# Task receipt: current-source Release build and test matrix

Task ID / parent milestone: `R03` / reproducible build and qualification
prerequisites

Scope: build the current source in Release mode with the application surface,
UnRAR, milter, on-access support, and the complete test harness enabled; bind
the build to the refreshed source manifest; and run the configured CTest
matrix.

Evidence identity:

- Source manifest SHA-256: `257282d76e128071449421a7eab0fdfe1ea2901e8b4f7c3da2e9e2483b96ae43`
- Build-cache `CMakeCache.txt` SHA-256: `ccb75198e830592855c11379070858f637ec45bdbcb97d923c4ca4ce9cf80ab3`
- Test binary: `/tmp/clamav-release-current-20260912/unit_tests/check_clamav`
- Test binary SHA-256: `3118e797e2a7ef3df12d2c831118b6c12e4393f090d20a0466e82f5c6c4c8c10`
- `clamscan` SHA-256: `b085b063e507da218d1ea5ed3436a91a7572bcf11462c4ec9ff3daa17eaa99c6`
- `clamd` SHA-256: `2edb23a67d30fe663e6af6669dee650382b178e09899b253fcf0e826a898063c`
- `clamdscan` SHA-256: `7ec20b8b5d1a0ceec6f005a50090e5ecdb2e79725018638086f2f88cc6735a3e`
- `freshclam` SHA-256: `3e5e89df1e0fd6d1d97e1ab1e00ebf42200df3c4d3afb026a1c486a5ae2dbff5`
- `sigtool` SHA-256: `e0d669e66c6d290f97046b77f57ee4f9e5da6ae8919c88608e0f3e2e1b54b1fd`
- `clamonacc` SHA-256: `dccdaefa3bb0cfdf9db5fdc25e16b5537b24708efcbdd4e69baca8ed64af9eb5`
- `clamav-milter` SHA-256: `6f2203447248ca686a7aa51e0875ea34c18c3ac8ead5f9049d6ff229de1ec2b0`
- `libclamav.so` SHA-256: `1798ba1f71bd11891cbf343b61073886a45a4ff7c4bb1fcd3b97ba5196621de1`
- Platform: disposable AArch64 Linux Docker toolchain (`Linux-6.12.76-linuxkit`)
- Compiler/toolchain: GCC 12.2; Rust `cargo 1.97.1`

Configuration:

```text
CMAKE_BUILD_TYPE=Release
ENABLE_APP=ON
ENABLE_CLAMONACC=ON
ENABLE_MILTER=ON
ENABLE_SHARED_LIB=ON
ENABLE_STATIC_LIB=ON
ENABLE_TESTS=ON
ENABLE_UNRAR=ON
ENABLE_LARGE_FILE_QUALIFICATION_TEST=OFF
```

The shared library and application binaries are built for normal application
linking. The private-entry-point `check_clamav` harness is deliberately linked
to the static library, matching the existing test design and enabling its
fault-injection wrappers. The harness source now conditionally omits those
wrapper-only assertions when a shared-only configuration is compiled, so the
Release test source remains configuration-safe.

Results:

- Release build: **passed**, all configured targets reached 100%.
- Release CTest matrix: **16/16 passed** in **156.91 seconds**.
- `libclamav`: passed, including the current parser and large-file regression
  coverage.
- Large-file control, source-guard, runtime-evidence, acceptance-schema,
  clamscan-admission, clamd-report, ZIP late-member, milter, and protocol
  tests: all passed.
- Rust, clamscan, clamd, freshclam, and sigtool tests: all passed.
- No host software was installed. The container emitted existing compiler
  warnings and reported optional development tools such as pytest, Valgrind,
  and rustfmt as unavailable; none caused a test failure.

This is Release development evidence only. The Docker target is AArch64, the
opt-in exact-32-GiB qualification test remains disabled, and the roadmap still
requires certified Linux x86-64, sanitizer, full-size boundary, production
CVD/database, service, ingress, Sonic1, and final release gates. No capability
was promoted and no GitHub workflow action, commit, push, or usage reset was
used.
