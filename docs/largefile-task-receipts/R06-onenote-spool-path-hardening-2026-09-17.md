# R06 OneNote spool pathname-replacement hardening — 2026-09-17

## Change

`libclamav_rust/onenote_parser/src/reader.rs` now retains the owner file
descriptor returned by `create_new` for spool writes. Reader handles are still
opened independently so multiple parser readers do not share a seek offset;
on Unix, the opened reader's device and inode must match the owner handle.

This removes the close-and-reopen window that could otherwise allow a replaced
spool pathname to receive parser output or be read as parser input.

Cleanup now also rechecks the owner device/inode before unlinking the spool
pathname on Unix. A replaced regular file is left intact during parser cleanup,
preventing a pathname race from deleting an unrelated file. Unexpected
pathname-inspection or removal errors now call the budget's cleanup-failure
hook; the scanner implementation marks the containing scan incomplete instead
of silently accepting an uncertain temporary-file cleanup.

Reader reopening now uses `O_NOFOLLOW|O_NONBLOCK` on Unix. This prevents a
replaced symlink from being followed and prevents a replaced FIFO from blocking
the parser before the owner identity check can reject it.

## Verification

- New symlink-replacement open, replaced-FIFO nonblocking open, replaced-
  regular-file cleanup, and overlong pathname cleanup regressions: passed.
- OneNote parser unit tests: 84 passed, including the overlong-path cleanup
  regression.
- OneNote parser integration tests: 5 passed.
- `cargo test --offline --manifest-path
  libclamav_rust/onenote_parser/Cargo.toml` — exit 0; 84 unit tests, 5
  integration tests, and one ignored doctest.
- `git diff --check`: passed.
- `cargo fmt --all -- --check`: unavailable because the configured Rust 1.97
  toolchain has no installed `rustfmt` component; no component was installed.
- `cargo test -p clamav_rust --no-run --target-dir
  /private/tmp/clamav-rust-target-current --message-format=short`: reached
  `openssl-sys v0.9.117` and stopped because this macOS worktree has no
  discoverable OpenSSL development installation or `pkg-config`. No package
  or Rust component was installed.

This is development verification only. It does not qualify full-size,
materialized, certified Linux x86-64, sanitizer, or release evidence.

## Current-source revalidation

The same current worktree was revalidated after the subsequent roadmap
changes with:

```text
CARGO_TARGET_DIR=/private/tmp/clamav-32gb-onenote-target cargo test --offline \
  --manifest-path libclamav_rust/onenote_parser/Cargo.toml
```

The command exited 0 with 84 unit tests, 5 integration tests, and one
ignored doctest. It compiled only against the already available local Cargo
cache and wrote build artifacts under `/private/tmp`; no package, compiler,
or Rust component was installed. The full C/Rust integration build remains
blocked by the missing local OpenSSL development installation described
above.
