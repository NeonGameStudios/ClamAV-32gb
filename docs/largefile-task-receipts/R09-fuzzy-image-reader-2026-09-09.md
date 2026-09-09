# Task receipt: R09 bounded fuzzy-image reader slice

Task ID / parent milestone: `R09` / `R00`

Scope: replace the scanner's whole-input fuzzy-image admission path with a
reader-backed Rust/C boundary that can inspect an encoded image larger than
the ordinary contiguous source budget while keeping decoded working memory
inside the shared resource policy. This is development evidence; it does not
promote the required R09 matcher rows.

Implementation:

- `libclamav_rust/src/fuzzy_hash.rs` now exposes
  `fuzzy_hash_calculate_image_fmap`, which feeds the image decoder through the
  existing bounded `FMapReader` and `BufReader` rather than creating a Rust
  slice over the encoded fmap.
- The decoder's declared output size is converted into a bounded working-set
  reservation with overflow checks and a 1 MiB floor for small images. The
  reservation is released after every decoder/hash result, including a
  decoder panic caught at the Rust boundary.
- Reader, timeout, parse, decoder-limit, and contiguous-budget failures map to
  typed ClamAV statuses and preserve the scanner's fail-visible,
  non-cacheable incomplete result behavior.
- `libclamav/scanners.c` now calls the fmap entry point directly. The former
  source-wide `fmap_need_off` and source-length contiguous reservation were
  removed; the legacy slice FFI remains available for compatibility callers.
- The native GIF test group now includes a positive regression with a valid
  2 MiB encoded comment under a 1.5 MiB contiguous cap, plus the existing
  admission-failure regression.

Validation:

- The canonical checkout was mounted read-only into the disposable
  `linux/amd64` `rust:1.97-bookworm` validation container.
- The Rust target rebuilt successfully with Cargo and the generated C header
  contains `fuzzy_hash_calculate_image_fmap(fmap_t *fmap, cli_ctx *scan_ctx,
  ...)`.
- The CMake-linked sanitizer test binary rebuilt successfully. The focused
  Check group passed `16` checks with `0` failures and `0` errors, including
  both fuzzy-image admission regressions, with no ASan/UBSan diagnostic.
- Source guards passed after regenerating the deterministic inventory for the
  current source tree. The local tools suite passed `145` tests with `2`
  expected skips, and the acceptance map/schema checks passed.

Boundaries:

- The Rust-only fuzzy-hash test harness was not used as the integration gate;
  it cannot link without the ClamAV C symbols that the crate intentionally
  imports. The CMake-linked native test is the applicable boundary and passed.
- The current development container has about `1.77 GiB` available and cannot
  satisfy the roadmap's `48 GiB` exact-edge qualification requirement.
  `matcher:rust-fuzzy-image-ffi-admission` and `matcher:fuzzy-image` remain
  pending for certified qualification evidence.
- No capability status was promoted. No commit, push, GitHub workflow action,
  usage reset, or banked reset was performed. Linux packages were installed
  only inside the disposable container; no host software was installed.
