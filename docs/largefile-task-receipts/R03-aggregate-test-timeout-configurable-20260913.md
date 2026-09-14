# R03 configurable aggregate-test timeout receipt — 2026-09-13

## Scope

Make the sanitizer aggregate `libclamav` test's outer Python timeout
explicitly configurable for slow qualification runners without changing its
existing default.

## Observed gap

The generated sanitizer CTest environment hard-coded
`CLAMAV_LIBCLAMAV_TEST_TIMEOUT=1200`. A direct current-source ARM64 run with
the C test-case timeout raised to 2,400 seconds still required more than the
outer 1,200-second allowance and stopped in scan-callback coverage. This
prevented a runner from selecting a larger, auditable aggregate-test budget
through normal CMake configuration.

## Changes

- Added the positive-integer cache setting
  `CLAMAV_LIBCLAMAV_TEST_TIMEOUT`, defaulting to `1200`, in
  `CMakeOptions.cmake`.
- Changed the sanitizer test environment in `unit_tests/CMakeLists.txt` to
  consume that cache setting instead of embedding the default literal.
- Updated the source guard to verify the default, validation, and propagation.

The default behavior is unchanged. A slow runner can now configure an
explicit value such as `-DCLAMAV_LIBCLAMAV_TEST_TIMEOUT=2700`; this setting
only controls the aggregate Python harness and does not weaken per-case C
timeouts or any production scan deadline.

## Verification

- `cmake -S /src -B /tmp/clamav-asan-current-20260912 -DCLAMAV_LIBCLAMAV_TEST_TIMEOUT=2700` — exit 0 in the disposable ARM64 build container.
- Generated `unit_tests/CTestTestfile.cmake` contained
  `CLAMAV_LIBCLAMAV_TEST_TIMEOUT=2700`.
- `sh tools/largefile_source_guards.sh` — exit 0; all 601 manifest/source
  controls passed.
- `sh -n tools/largefile_runtime_gate.sh tools/largefile_runtime_evidence_check.sh tools/largefile_service_qualification.sh tools/largefile_service_evidence_check.sh` — exit 0.
- `python3 tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — exit 0.
- `python3 -B tools/largefile_acceptance_cases.py --check-map` — exit 0; 601 capabilities.
- `git diff --check` — exit 0.

Follow-up verification (2026-09-13 UTC):

- The existing current-source ASan `check_clamav` target rebuilt successfully
  from `/src` after the CMake change.
- The ASan acceptance/source controls `largefile_source_guards`,
  `largefile_acceptance_case_schema`, `largefile_acceptance_case_resources`,
  and `largefile_acceptance_resource_capture` passed 4/4.
- An isolated configure with
  `-DCLAMAV_LIBCLAMAV_TEST_TIMEOUT=0` failed closed with the expected
  `CLAMAV_LIBCLAMAV_TEST_TIMEOUT must be a positive integer` diagnostic.
- These checks validate configuration propagation and rejection behavior; they
  do not change the incomplete aggregate sanitizer result or qualify any
  capability.

No aggregate sanitizer pass is claimed by this change. The current ARM64
aggregate result remains incomplete at 2,700.418 seconds; certified Linux
x86-64 aggregate evidence is still required by the roadmap.

State: `development-verified`.
