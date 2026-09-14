# R03 current-source `ENABLE_WERROR` flag propagation — 2026-09-14

Task ID / parent milestone: `R03` / `R10`.

The dirty canonical working tree remained at HEAD
`8e837b88c89874b180a1a25f22d287f7d6be29db`. The current-source manifest
contains 1,697 entries and has SHA-256
`deca4540a2eecdbd6236ae6fc524e8cc95e99bdff30717568e4903bfaf81446a`.

The CMake warning-flag helper previously initialized its accumulator from empty
on every invocation. Since the top-level build appends `-Werror` first and
`-Wall`/`-Wextra`/`-Wformat-security` later, that implementation discarded
`-Werror` before generating the final warning flags. Both C and C++ helper
accumulators now start from the caller's existing variable value.

## Verification

Using the retained ARM64 `rust:1.97-bookworm` Docker container
(`clamav-current-rust-build-20260911`) and no newly installed software:

* The isolated configuration
  `/tmp/clamav-werror-fixed-20260914` was generated with
  `-DENABLE_WERROR=ON`, tests disabled, and application/milter/clamonacc/UnRAR
  enabled. CMake completed successfully and reported:
  `WARNCFLAGS: -Werror -Wall -Wextra -Wformat-security`. Its
  `CMakeCache.txt` SHA-256 is
  `097292a43b9376cb1d6a0d59f08447e1606f09c5021617f3d593267b820f5214`.
* The focused `clamav` target was started with `cmake --build ... --target
  clamav -j2` and failed on existing bundled regex signedness diagnostics in
  `libclamav/regex/regcomp.c` (`-Werror=sign-compare`). This is expected
  failure evidence that Werror is now active; the build was stopped after that
  deterministic first library failure while unrelated Rust dependencies were
  still compiling in parallel.
* The source-level CMake change is limited to
  `cmake/ExtractValidFlags.cmake`; no workflow, commit, push, or capability
  promotion was performed.

State: `development-verified; global-warning-clean-qualification-pending`.
The bundled regex and other existing warning sites require a separately scoped
warning-cleanup pass before `ENABLE_WERROR` can qualify for release.

The refreshed capability manifest SHA-256 is
`611c982fa02638231d9681206c6cdc6ed152f6fd91cbdd4d6739e56fe7bab3f3`; the
fresh readiness snapshot SHA-256 is
`5ee24d35676236d12209da72af25c6c135bfef4ec96dc6dd6b7fd5ace485ae43`.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
