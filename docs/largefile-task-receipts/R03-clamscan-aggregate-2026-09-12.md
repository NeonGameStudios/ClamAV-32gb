# Task receipt: current-source clamscan aggregate and test discovery

Task ID / parent milestone: `R03` / `R00`

Scope: make the CMake fallback test command execute the complete `clamscan`
Python suite when pytest is unavailable, then reconcile stale expectations
with the roadmap's fail-visible parser and scan-result contracts.

## Harness correction

The prior CMake command was equivalent to `python3 -m unittest --verbose
clamscan`. Because `unit_tests/clamscan` intentionally has no `__init__.py`,
that command reported `Ran 0 tests` while CTest passed. `unit_tests/CMakeLists.txt`
now uses `python3 -m unittest discover -s clamscan -p '*_test.py' --verbose`
for the unittest fallback, and `tools/largefile_source_guards.sh` pins the
discovery command so the coverage cannot silently regress.

## Test-contract updates

- The aggregate file set now classifies the current MEW, YC, and recursion
  fixtures as fail-closed parser errors.
- Import-hash detection remains visible when a sibling PE analysis is
  incomplete, preserving detection precedence.
- ZIP concatenation and incomplete central-directory cases now require the
  strict no-local-header-fallback error contract.
- The CVD detached-signature case converts the historical fixture to the
  current TAR format and signs it with the repository's existing test key,
  preserving the FIPS detached-signature assertion.
- The repaired PDF URI fixture is expected to scan clean while retaining its
  metadata URI checks.
- PE certificate/TLS-targeted signatures are excluded only when the current
  embedded-PE analysis is incomplete; the block-certificate detection remains
  required.

## Evidence

- Container: `clamav-current-rust-build-20260911`, image `rust:1.97-bookworm`.
- Build directory: `/tmp/clamav-release-current-20260912`.
- Scanner SHA-256:
  `b085b063e507da218d1ea5ed3436a91a7572bcf11462c4ec9ff3daa17eaa99c6`.
- CMakeCache SHA-256:
  `cf3622e210201cf7f5ce1ca92167de34585eb58353441f03d4ecbcf50cb5b3b7`.
- Current source manifest SHA-256:
  `13247cfac5c772a5d7e429a05cec1c5bdc041f82e5175a2caa6353f0e357916a`.
- `ctest -R '^clamscan$'`: 127 tests passed, 1 skipped, 0 failures.
- Broader current-source subset excluding the separately run `clamd` and
  source-guard tests: 14/14 passed.
- `ctest -R '^clamd$'`: 1/1 passed.
- Host source guards, large-file snapshot/readiness checks, diff check, and
  Python AST syntax checks passed.

This is development verification only. It does not satisfy the roadmap's
full-size corpus, sanitizer, certified Linux x86-64, production-CVD/service,
Sonic1, or final release gates.
