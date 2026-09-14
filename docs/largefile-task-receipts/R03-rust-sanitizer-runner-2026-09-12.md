# Task receipt: R03 Rust sanitizer CTest runner — 2026-09-12

Task ID / parent milestone: `R03` / `R00`.

Exact capability kind:id list: `feature:ENABLE_TESTS`,
`feature:ENABLE_STATIC_LIB` (sanitizer test plumbing only; no capability was
promoted).

Starting commit and working-tree/source identity: branch
`largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. Final current-source manifest SHA-256 after this
slice's source and guard changes:
`3b3cf4f6e176fe2fbb5f1be41976df55a20c294bbd974a27dac3680905a327ef`.
No host dependency installation, usage reset, commit, push, or GitHub
workflow action was used.

Prerequisites verified: the existing disposable
`clamav-current-rust-build-20260911` container is `rust:1.97-bookworm` on
ARM64. GCC 12.2, Cargo/Rust 1.97.1, CMake, Check, and the previously installed
container-only development dependencies were available. The sanitizer build
was configured from the current source at `/src` into
`/tmp/clamav-current-asan` with C/C++ ASan/UBSan flags, static libraries,
tests, and large-file defaults disabled.

Observed gap and expected behavior: a Rust test executable linked against
sanitized C archives must start with the C sanitizer runtimes in the loader's
initial library list. The prior CTest command passed the sanitizer linker
flags to Cargo but did not provide a target-specific Cargo runner, so the
Rust test aborted with `ASan runtime does not come first` before running its
tests. Cargo and rustc themselves must not inherit `LD_PRELOAD`, because that
turns their own allocator lifetime into a false sanitizer failure.

Changes made:

- `cmake/FindRust.cmake` now derives the compiler-selected `libasan.so` and
  `libubsan.so` paths when the CTest link flags request both runtimes.
- The Rust CTest command now sets
  `CARGO_TARGET_<TARGET>_RUNNER=env LD_PRELOAD=<asan>:<ubsan>`, using the
  actual normalized Rust target instead of a hard-coded architecture. The
  preload is applied to the test executable by Cargo's runner, not to Cargo
  or rustc.
- `tools/largefile_source_guards.sh` pins the runner and missing-runtime
  failure contract.
- `unit_tests/libclamav_test.py` accepts a validated, explicit aggregate-test
  timeout override, and `unit_tests/testcase.py` now forwards execution
  keyword arguments to the executor instead of nesting and discarding them.
- `unit_tests/CMakeLists.txt` supplies a 1200-second override only when
  sanitizer linker flags are enabled, leaving ordinary test runs at 600
  seconds.

Verification performed:

- Fresh current-source sanitizer build completed at 100%, including
  `check_clamav`, `clamscan`, and `clamd`.
- The reader-backed OneNote regression under ASan/UBSan passed 3/3 checks
  with no sanitizer diagnostics.
- Direct execution of the generated Rust unit-test binary with the selected
  sanitizer runtimes preloaded passed 159/159 tests with no ASan/UBSan
  diagnostics.
- Before the runner correction, the selected six-target sanitizer CTest run
  had two failures: `libclamav` timed out after 600 seconds following the
  existing `traverse_to: Failed open payload` diagnostic, and
  `libclamav_rust` aborted before tests with the loader-order error. The
  `clamscan`, `clamd`, `freshclam`, and `sigtool` targets passed.
- After CMake reconfiguration, the corrected CTest target
  `ctest --test-dir /tmp/clamav-current-asan --output-on-failure -R
  '^libclamav_rust$'` passed 1/1 in 1.18 seconds. The generated test command
  contains the ARM64-specific Cargo runner and compiler-derived runtime
  paths.
- To isolate the remaining aggregate timeout, the complete `cl_suite/cl_api`
  group was run directly with the same ASan/UBSan settings and completed
  520/520 in 10 minutes 23 seconds. The three action-source tests passed under
  sanitizers, and their expected replaced-symlink diagnostic was the only
  `traverse_to: Failed open payload` occurrence; no ASan/UBSan diagnostic was
  emitted.
- After fixing the Python executor keyword forwarding, the restricted
  `libclamav` CTest invocation with `CK_RUN_CASE=cl_api` passed 1/1 in 606.66
  seconds, completing all 520 checks. This is the first CTest-level proof that
  the sanitizer allowance is honored; the unfiltered `cl_suite` remains a
  separate full-suite run to be scheduled on a certified runner.

Full-size/certified evidence: not produced. This is ARM64 Docker development
evidence, not the roadmap's certified Linux x86-64 Release/sanitizer profile,
nightly `-Zsanitizer=address` Rust requirement, full-size workload, R04
acceptance record, production-CVD/service, or final release qualification.

Remaining failures / next slice: the unfiltered `cl_suite` sanitizer run and
the roadmap's certified x86-64/nightly Rust profile remain open; the current
ARM64 CTest evidence is development-only. Full-size materialized cases,
capability-specific records, and final release evidence are also still
required.

State: `development-verified` for the target-specific Rust sanitizer runner;
R03 certification remains pending.

## Follow-up — 2026-09-13

The current source contained a second sanitizer environment block in
`unit_tests/CMakeLists.txt` that appended the hard-coded
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER` after the target-aware logic in
`cmake/FindRust.cmake`. That duplicate block was removed. The
`largefile_clamscan_admission` CTest registration was also gated on
`ENABLE_APP`, because library-only configurations do not define the
`clamscan` target.

Verification from the existing ARM64 disposable build container:

- The full application CMake configure completed with static libraries,
  applications, tests, C ASan/UBSan flags, and large-file defaults disabled;
  no packages were installed.
- `ctest --test-dir /tmp/clamav-current-build -N -V -R '^libclamav_rust$'`
  generated `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER=env
  LD_PRELOAD=/usr/bin/../lib/gcc/aarch64-linux-gnu/12/libasan.so:/usr/bin/../lib/gcc/aarch64-linux-gnu/12/libubsan.so`
  and passed `--target aarch64-unknown-linux-gnu` to Cargo.
- In the preserved full application sanitizer build,
  `ctest --test-dir /tmp/clamav-asan-current-20260912 --output-on-failure
  -R '^libclamav_rust$'` passed `1/1` in `59.74` seconds.
- `tools/largefile_source_guards.sh` and `git diff --check` passed.
- An alternate local toolchain image lacked the OpenSSL development header
  `openssl/opensslconf.h`, but the preserved full sanitizer container supplied
  the existing headers and completed the focused CTest run; packages were
  intentionally not installed.

Current-source manifest SHA-256: `83c55df9a3eb4ca55ac7b6fa0f24f24d6aa88adc50320c69fd60a2c187c7746d`
(1,697 entries). This remains ARM64 development/configuration evidence, not
the roadmap's certified Linux x86-64 Release/sanitizer result. The exact
32-GiB workload, nightly Rust sanitizer profile, production service/CVD,
privileged fanotify, Sonic1, and final release gates remain open.

## Full current application sanitizer revalidation — 2026-09-13

The preserved full application build was rebuilt from the current source at
single-job concurrency, reaching `100%` and producing `clamscan`, `clamd`,
`clamonacc`, `clamav-milter`, `sigtool`, and all added pool test binaries.
The first post-build application subset found one real LeakSanitizer failure
in `largefile_onaccess_config_admission`; that failure is recorded in the R13
receipt and was fixed before the focused rerun.

Current evidence from the rebuilt tree:

- The four pool/configuration tests pass `4/4` under C ASan/UBSan with
  LeakSanitizer.
- The rebuilt `clamscan`, `clamd`, `freshclam`, `sigtool`, milter protocol, and
  release-control tests pass; combined with the post-fix rerun of the single
  previously failing configuration test, the 27-test non-aggregate subset is
  covered `27/27`.
- The bounded CTest invocation with `CK_RUN_SUITE=cl_suite` and
  `CK_RUN_CASE=cl_api` passes `1/1`, completing all `520` `cl_api` checks in
  `610.67` seconds without sanitizer diagnostics.
- The unfiltered `libclamav` test remains too slow for the current ARM64
  development wrapper: it reached the configured `1,200`-second timeout while
  running the complete suite. Its timeout is not being relabeled as a code
  pass; further Check TCase groups must be run in bounded invocations.

Current-source manifest SHA-256 after the cleanup and derived-inventory
refresh: `5a2baef1ece4b0d64579fb8380b03f62b751e79dd584342c318c9fcd9aeec593`
(1,697 entries). This remains development ARM64 evidence and does not satisfy
certified Linux x86-64, exact 32-GiB/materialized, production-CVD/service,
privileged fanotify, Sonic1, or final release qualification.

## Bounded parser-family sanitizer follow-up — 2026-09-13

To avoid the unfiltered aggregate timeout while retaining meaningful current
source coverage, the existing Check TCase selector was used for bounded
invocations. Each invocation passed `1/1` at the CTest level with no ASan/UBSan
diagnostics: `rust_onenote`, `hfs_fork`, `rust_alz`, `rust_lha`, `7z`, `zip`,
`pdf`, `required_unsupported`, `parser_regressions`, `rust_map`, `7z_sfx`,
`hfs_map`, and `mspack`. The complete `cl_api` TCase separately passed all
`520` checks in `610.67` seconds. The container's one-hour lifetime expired
between two checks; restarting the same preserved container completed the
remaining cases, with no source or build change.

These are current-source ARM64 development sanitizer checks. They do not
replace the full unfiltered Check suite, certified Linux x86-64, exact
32-GiB/materialized edges, production-CVD/service, privileged fanotify,
Sonic1, or final release qualification.
