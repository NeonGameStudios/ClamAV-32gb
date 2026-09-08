# Task receipt: R03 development build probe

Task ID / parent milestone: `R03` / `R00`

Canonical source: `/Volumes/512gbNVME/github-external/ClamAV-32gb`, branch
`largefile-roadmap-qualification`. Existing dirty changes were preserved. No
immutable qualification candidate was declared.

Purpose: determine whether the already-installed local Docker images can provide
a development build path while the authorized Linux x86-64 runner is
unavailable. This is not certified runner evidence and does not promote any
capability.

Environment: the already-installed
`clamav-largefile-local-toolchain2:latest` image supplied CMake 3.25.1,
Clang 16.0.6 and Rust 1.97.1 on ARM64/aarch64. The repository was mounted
read-only with an out-of-tree build directory at
`/private/tmp/clamav-largefile-build`. Missing development packages were
installed only inside disposable `docker run --rm` containers; no host or
repository installation was performed. Locked Rust git/registry dependencies
were downloaded only into the disposable build container/cache.

Observed configure results:

- Tests-enabled configure stopped at missing `libcheck`.
- Tests-disabled development configure detected OpenSSL 3.0.20, zlib 1.2.13,
  bzip2 1.0.8, libxml2 2.9.14 and PCRE2, then stopped at missing json-c
  development headers and library.
- A fresh configure of the current roadmap checkout initially stopped at
  `CMakeLists.txt:533` (`find_package(JSONC REQUIRED)`) because the image did
  not contain JSON-C, Check, curl, milter, OpenSSL, or zlib development files.
  Adding those packages inside the disposable container allowed configure to
  complete without disabling required application features.
- The resolved development configuration was `Debug`, `ENABLE_TESTS=OFF`,
  shared libclamav, Rust enabled, PCRE2, JSON-C, OpenSSL, zlib, milter,
  clamonacc, and UnRAR enabled. `ENABLE_LARGE_FILE_DEFAULTS` and
  `ENABLE_LARGE_FILE_QUALIFICATION_TEST` remained off, so this is not a
  qualification configuration.
- The documented static test shape (`ENABLE_TESTS=ON`,
  `ENABLE_STATIC_LIB=ON`, `ENABLE_SHARED_LIB=OFF`) configured and linked all
  test targets. The first shared-library test shape was rejected because the
  CMake test wrappers are intentionally enabled only for static tests.
- The host remains macOS/ARM64; the roadmap requires a Linux x86-64 runner with
  the certified resources. No Release, sanitizer, CTest, daemon, or full-size
  qualification evidence was retained.
- An offline Rust-only build was not complete because Cargo lacked the locked
  `clam-sigutil` git dependency. With network access enabled only inside the
  disposable build container, the locked Rust dependencies were fetched and
  the full development build completed.

Commands and exits:

- Temporary local-layer Docker image build — exit 0.
- CMake with tests enabled — exit 1 at missing `libcheck`.
- CMake development configure with tests disabled — initially exit 1 at
  missing JSON-C development files; after disposable package installation,
  exit 0.
- Current-source CMake development build with the locked Rust dependencies —
  exit 0 at 100%; CMake linked the main application, daemon, client, milter,
  on-access, bytecode, signature, submission, and database-updater binaries.
- Retained build artifacts include `clamscan`, `clamd`, `clamdscan`,
  `clamonacc`, `clamav-milter`, `clambc`, `sigtool`, `clamsubmit`, `freshclam`,
  and `clamdtop`; `clamscan` was identified as an ARM aarch64 ELF with debug
  information.
- Disposable startup checks loaded the built shared libraries successfully:
  `clamscan --version`, `clambc --version`, `sigtool --version`, and
  `freshclam --help` returned successfully. `clamd`, `clamdscan`, and
  `clamonacc` loaded far enough to report only the expected absent default
  configuration file. No daemon or production database run was attempted.
- A functional scanner smoke check used the freshly built static `clamscan`,
  the repository's bundled certificate directory, the bundled HDB test
  database, and the generated `clam.impl.zip` fixture. It reported
  `ClamAV-Test-File.UNOFFICIAL FOUND`, scanned one file, and returned the
  expected detection exit code 1.
- The Rust test seam was corrected so `MappedInput` uses Rust-only test
  helpers instead of exporting symbols that duplicate the static C library.
  After the change, the isolated `libclamav_rust` CTest passed all 143 tests
  when its writable temporary-file directory was provided, and the normal
  non-test Rust target rebuilt successfully. A complete CTest pass was not
  claimed: `check_clamav` still segfaulted on this ARM64 container, daemon
  tests could not bind its Unix socket or pass x86-64 admission, and the
  source-guard test observed the intentionally dirty generated inventory.

Conclusion: a coherent ARM64 development build is now verified, which removes
the local source/configure/build blocker. R03 remains open for the roadmap's
actual deliverable: a certified Linux x86-64 Release build with tests,
sanitizers, admission checks, retained identities, and the required runner
resources. The disposable Debug build is not a qualification candidate and
does not promote any capability or release readiness.

State: `development-verified`; certified qualification remains blocked.
