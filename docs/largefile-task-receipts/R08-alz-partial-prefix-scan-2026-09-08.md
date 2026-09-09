# Task receipt: R08 ALZ partial-prefix scanning

Task ID / parent milestone: `R08` / `R00`

Date: 2026-09-08

Scope: correct the current-source ALZ scanner so bounded or malformed members
still have their available output inspected, while preserving the original
scan-limit or parser-error result.

Observed defect:

- The ALZ deflate and stored extractors aborted their temporary member spool
  as soon as a decompressed-size limit or declared-size/CRC/trailing-data
  mismatch was observed.
- The public `clamscan` regressions therefore missed a signature in a valid
  bounded prefix and returned an error instead of the detection.
- This was reproducible against the current source with
  `clamscan.alz_test.TC.test_deflate_limit_uses_decompressed_size` and
  `clamscan.alz_test.TC.test_inflated_header_size_does_not_skip_extraction`.

Implementation:

- Added `ExtractSink::finish_partial()`, which scans the accumulated output
  and discards an empty partial member without treating it as a complete
  archive entry.
- Deflate, stored, and bzip2 paths now scan the bounded prefix before returning
  `ScanLimitExceeded` or `Extract` for size, checksum, truncation, decoder, or
  trailing-data errors.
- Backing-store read failures, timeouts, sink failures, and allocation/stop
  failures still abort immediately and preserve their hard status.
- Updated Rust unit expectations and the source guards to pin the new
  detection-before-error contract; regenerated the line-numbered large-file
  inventory from the canonical checkout.

Verification in disposable `clamav-largefile-local-toolchain2:latest` ARM64
development container:

- `cmake --build /tmp/clamav-largefile-static-build --target clamscan -j2` —
  passed.
- `cmake --build /tmp/clamav-largefile-static-build --target check_clamav -j2`
  — passed.
- Rust CTest target `libclamav_rust` — 152/152 tests passed.
- Focused `CK_RUN_SUITE=cl_suite CK_RUN_CASE=rust_alz` — 2/2 checks passed.
- Public `python3 -m unittest -v clamscan.alz_test
  clamscan.lzh_lha_archive_test` — 13/13 tests passed. The two previously
  failing ALZ cases now return the expected detection with CLI status 1; the
  clean limit control still returns status 2 and remains incomplete.
- Rebuilt `clamscan` SHA-256:
  `a697458bf611aa47601a15954452af62d3b6a24fae1b85c55ef04bc135f06b42`.
- Build-cache `CMakeCache.txt` SHA-256:
  `9b82dbf4f5d10c40e4a31d83ff5c8a3d6ebb0da20b5b7473ebf2f88668cf8fc6`.

Repository controls:

- `sh tools/largefile_source_guards.sh` — passed; 597 capability entries and
  all local evidence controls passed.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` — passed.
- `git diff --check` — passed.
- Readiness remains intentionally blocked with 597 total rows, 0 qualified,
  143 bounded, 440 pending, 14 allowlisted unsupported, 583 blocked, and 80
  parser rows blocked.

This is development evidence only. It does not promote any capability or
replace the required certified Linux x86-64 Release/sanitizer, full-size,
daemon, ingress, resource, or fanotify qualification evidence. No commit or
push was made, and no usage-reset credit was used.
