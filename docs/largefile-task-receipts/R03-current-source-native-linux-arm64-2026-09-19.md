# R03 current-source native Linux build receipt — 2026-09-19

## Scope

This receipt records a current-source, coherent Linux development build against
the `largefile-roadmap-qualification` branch. It advances the R03 build
boundary and provides supporting evidence for R08/R10/R13 work; it is not a
certified release qualification.

The source tree was the canonical `/Volumes/512gbNVME/github-external/ClamAV-32gb`
checkout. The pre-change committed source was `c8ddf922`; the fixes recorded by
this receipt are committed immediately afterward in the repository history.

## Build environment

- Disposable ARM64 `rust:1.97-bookworm` Linux container.
- Exact Rust toolchain: Rust `1.97.1`,
  `aarch64-unknown-linux-gnu` (`cargo`, `rustc`, and `rustdoc`).
- CMake configured out of tree with shared and static libclamav, applications,
  tests, clamonacc, milter, UnRAR, and Rust consumer support enabled.
- CMake test temporary root: `/tmp/clamav-test-tmp` inside the container.
- Existing host Cargo cache was mounted read-only; the build used a disposable
  container-local `CARGO_HOME` and `CARGO_TARGET_DIR`.
- Development dependencies were installed only inside the disposable
  container; no host or repository software was installed.

## Results

- The complete CMake build reached 100% and built the C and Rust components
  coherently, including libclamav, clamd, clamdscan, clamonacc, milter,
  clamscan, clamconf, clambc, clamsubmit, freshclam, sigtool, and clamdtop.
- Focused `libclamav` and `libclamav_rust` CTest run: **2/2 passed**.
- Focused source-guard and clamonacc deadline CTest run: **2/2 passed**.
- The 30 non-Rust tests in the complete 31-test CTest suite passed. The Rust
  release test remained in first-time dependency compilation and exceeded the
  bounded 360-second test command timeout; it did not report a test failure.
- Service-evidence regression: **29 + 18 + 23 tests passed**, with two
  platform-specific skips.
- Clamonacc stream-deadline regression passed.
- Repository Python tests: **207 passed, 2 skipped**.
- Source guards and acceptance checks passed, including the 604-entry
  capability manifest and release-readiness checks.
- `32gb-current-snapshot.md` passed its freshness/status validation.

## Source and fixture corrections

- Restored the missing `#endif` in `clamd/clamd_others.c`, allowing the full
  application build to parse and compile.
- Corrected the HFS+ ExtentOverflow fixture and malformed-tail mutation offsets
  in `unit_tests/check_clamav.c` so the test exercises the intended overflow
  payload and rejection path.
- Made the BM source guard match the actual one-line `cli_qsort` call.
- Made the strict C11 clamonacc helper declare POSIX APIs explicitly.
- Made the synthetic clean service log satisfy the explicit `input: OK`
  evidence contract.
- Regenerated `docs/largefile-inventory.tsv` after the fixture edits so source
  locations and inventory provenance agree.

## Qualification boundary

This is ARM64 development evidence only. It does not establish the roadmap's
certified Linux x86-64 Release build, C ASan/UBSan build, Rust address-
instrumented build, production database run, exact materialized 32-GiB edge,
full ingress/on-access parity, resource measurements, or final release canary.
No capability rows were promoted from this receipt.

The current readiness remains blocked at:

```
capability_total=604
capability_qualified=0
capability_bounded=147
capability_pending=443
capability_unsupported=14
capability_unsupported_required=0
capability_blocked=590
release_readiness=blocked
```

No MCP-SSH state, GitHub workflow, or usage-reset credit was used for this
receipt.
