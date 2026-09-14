# R03 current-source build and test rebind — 2026-09-13

## Source identity

- Repository source is mounted at `/src` from the canonical working tree.
- Source manifest: 1,697 entries,
  `bf4f97b6f7d1673824825a74ea8045e2e54217770dffe711d966540ba7aa6bd7`.
- The working tree remains intentionally dirty; no commit, push, branch, or
  workflow action was performed.

## Builds

The existing Docker container `clamav-current-rust-build-20260911` was
reconfigured and rebuilt without installing software.

- Release tree: `/tmp/clamav-release-current-20260913`
- Release `CMakeCache.txt`: `314dbe0e86c0783eefcb9bd145fa7b2de8a8cd7775974deb6273755d7b213da3`
- Release `check_clamav`: `395d236f58f664a2cd8bbe8718e3e1e14fc4c563d2764024ae32f75c0581f067`
- ASan/UBSan tree: `/tmp/clamav-asan-current-20260912`
- ASan/UBSan `CMakeCache.txt`: `146cc96133c6ce912fa4b9e2ae9e6906c060de4a4f4ba61ed3858a5fd6690d2e`
- ASan/UBSan `check_clamav`: `3e5346b491693581b7a76ceaa6a4df8d0a32fde860802a80c9eea00074f46d3e`

Both builds reached 100%.

## Test results

- Release CTest: **28/28 passed** in 217.36 seconds, including the complete
  Release `libclamav` suite, Rust, all large-file controls, `clamscan`,
  `clamd`, `clamdscan`, milter, freshclam, and sigtool.
- ASan/UBSan admission controls 1–4 passed before the aggregate run was
  interrupted by the disposable container's one-hour PID-1 lifetime.
- Isolated ASan/UBSan `libclamav` CTest completed with a timeout at 1,200.62
  seconds. It emitted the existing expected `traverse_to: Failed open payload`
  diagnostic and no AddressSanitizer, UndefinedBehaviorSanitizer, or runtime
  error diagnostic. This is not a passing full sanitizer result.
- Host `largefile_*_test.py` harness: **172 passed**, 2 Linux-only tests
  skipped on macOS, in 9.931 seconds.

## Disposition

The current-source ARM64 Release application and control matrix are
development-verified. The aggregate sanitizer suite remains open at its
configured timeout boundary. Certified Linux x86-64 execution, full-size
materialized cases, production CVD/service behavior, privileged fanotify
evidence, independent format-8 bytecode/JIT evidence, and final release
readiness remain required. No capability was promoted.
