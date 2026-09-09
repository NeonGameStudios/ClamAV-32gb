# Task receipt: current-source C AddressSanitizer and UndefinedBehaviorSanitizer slice

Task IDs / parent milestones: `R03` / `R10`

Scope: build the canonical current checkout's C scanner and daemon targets
with explicit AddressSanitizer and UndefinedBehaviorSanitizer instrumentation
and exercise the application paths in a disposable Linux x86-64 container.
This is development evidence; it is not the roadmap's certified 32-GiB
qualification or a Rust sanitizer candidate.

Build identity:

- source: `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- branch: `largefile-roadmap-qualification`
- HEAD at capture: `41cde8160286813f0f98e109c1450e40ff4117fb`
- source mounted read-only at `/src`
- build output: `/private/tmp/clamav-32gb-current-sanitize-target/cmake-sanitize`
- container: `clamav-32gb-current-sanitize-20260909`
- image: `rust:1.97-bookworm`; platform: `linux/amd64`

Instrumentation and build:

- GCC `12.2.0`, CMake `3.25.1`, Cargo/Rust `1.97.1`
- C and C++ flags: `-fsanitize=address,undefined -fno-omit-frame-pointer`
- executable and shared-library link flags included both sanitizers
- `clamscan`, `clamdscan`, `clamd`, `check_clamav`, and `check_clamd` built
  successfully; the dynamic `clamunrar` and `clamunrar_iface` modules were
  also built for the shared-library runtime
- the generated compile database contains the sanitizer flags; the scanner
  binary's dynamic section requires `libasan.so.8` and `libubsan.so.1`
- Rust was built with the stable toolchain and was not address-instrumented;
  the roadmap's nightly Rust sanitizer requirement remains open

Runtime results:

- instrumented `clamscan` smoke test detected
  `ClamAV-Test-File.UNOFFICIAL FOUND` from the generated HDB fixture
- instrumented daemon version, PING/PONG, scan, fdpass, stream, multiscan,
  limit, cleanup, and lifecycle checks passed all 15 Python test cases in
  `50.01` seconds
- the native `libclamav` Check run passed all 2,836 checks through CTest in
  `459.23` seconds with no failures or errors
- no AddressSanitizer or UndefinedBehaviorSanitizer diagnostic was emitted

Retained artifact hashes:

- `clamscan`: `41bedbc0c0b3cd76051f43d713746a12ab1c351eef0cd047a01a113ce25992ce`
- `clamd`: `446961e62cde7449a6570d529265d6568acedd5ac0982cd4b9e98bd19377fa88`
- `clamdscan`: `cf617e646933738a0adde6d51d9fba52b8528ac482b04ba90d5cdbd236e9e4e3`
- `check_clamav`: `debb5dd0775cfeae2ec4d186becbc8a3cea15b554cd86d42d92099dcfe382525`
- `check_clamd`: `e8d3ef6cd0c6eaea4c06d34d423fea7a4e16dc44a55393781208e637d17362a0`

Interpretation and boundaries:

- the C application sanitizer slice is build-complete and passed its full
  native and daemon test suites after the required dynamic UnRAR modules were
  included
- the earlier coherent non-sanitized current-source Docker build remains the
  authoritative green development build (`16/16` serial CTest)
- this container has about `1.77 GiB` available memory, so it cannot satisfy
  the roadmap's `48 GiB` exact-edge admission gate
- no capability was promoted, and R06's modern OneNote reader and the seven
  required R09 rows remain open

No commit, push, GitHub workflow action, usage reset, or banked reset was
performed. Linux build packages were installed only inside the disposable
Docker container; no host Linux sysroot was installed.

Mixed C/Rust sanitizer CTest follow-up (2026-09-09 UTC):

- The current-source Rust test target initially linked the sanitizer-built C
  archive without its ASan/UBSan runtimes because Cargo's test linker uses
  `-nodefaultlibs`. The final bridge emits `-lasan` and `-lubsan` only for
  `CARGO_CMD=test`, and gives the Rust test executable a target-specific
  runner with the compiler-derived sanitizer runtimes preloaded. Normal Rust
  library builds are unchanged.
- After the correction, the focused `libclamav_rust` CTest passed 1/1 with
  ASan/UBSan. The current-source `freshclam` and `sigtool` focused tests passed
  2/2 after their concrete build targets were prepared; the milter quota,
  clamscan, clamd, MBR, and MHTML focused controls also passed.
- A complete configured CTest pass was not called green: the unfiltered
  `cl_suite` hit its 600-second timeout after `traverse_to: Failed open
  payload`, and two repo-wide Python controls exceeded their disposable
  container time limits despite passing in standalone runs. No sanitizer
  diagnostic was attributed to the focused passing cases.

This follow-up repairs development-test plumbing; it does not establish the
roadmap's certified x86-64 runner, nightly Rust sanitizer, full-size workload,
or release qualification.
