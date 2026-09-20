# R03 local build boundary — 2026-09-20

## Scope

Revalidate the current qualification checkout's locally available build paths
without installing software or weakening required Rust/CMake features.

## Current-source evidence

- Checkout: branch `largefile-roadmap-qualification`, revision `b9dc0784`.
- `cargo test --offline --manifest-path
  libclamav_rust/onenote_parser/Cargo.toml` passed **85 unit tests**, **6
  integration tests**, and **1 ignored doctest** against the current vendored
  OneNote parser.
- Host `CARGO_TARGET_DIR=/private/tmp/clamav-rust-current-target cargo check
  --offline --locked -p clamav_rust` reached `openssl-sys` but failed because
  the host has no discoverable OpenSSL development installation or `pkg-config`
  (`exit 101`).
- The pre-existing Linux `rust:1.97-bookworm` image contains Rust `1.97.1`.
  With the current checkout and existing Cargo registry/Git caches mounted
  read-only, the equivalent offline command completed successfully:
  `rustup run 1.97.1 cargo check --offline --locked --target-dir
  /tmp/clamav-rust-current-target -p clamav_rust` (`exit 0`, 2m38s).
- The same isolated image and cache setup reached the full `cargo test`
  link step but failed because the standalone Rust test binary is not linked
  with the native ClamAV C library. The linker reported unresolved current
  C/Rust FFI symbols including `cli_errmsg`, `cli_checktimelimit`,
  `cli_mark_scan_incomplete`, and `cli_versig` (`exit 101`).
- The existing `clamav-largefile-local-toolchain2:latest` Docker image has
  CMake, Clang, and Make, but no Cargo, JSON-C development package, or Check
  package. A read-only CMake configure therefore stops at the required Cargo
  1.97 check before producing a build (`exit 1`).
- The existing `rust:1.97-bookworm` image supplies GCC, OpenSSL development
  support, and Rust `1.97.1`, but has no CMake, JSON-C, or Check. The two
  pre-existing images therefore complement one another but neither is a
  complete native ClamAV build environment; no image composition or package
  installation was attempted.

No host software was installed, no repository dependency was changed, and no
feature was disabled to obtain a partial pass.

## Boundary and next action

This is a partial R03 advance, not release qualification. Rust compilation is
now proven in an existing pinned Linux image; integrated Rust tests and the
full C/Rust build still require a coherent CMake-built native library plus
JSON-C, Check, and the required optional libraries. No software was installed,
downloaded, or enabled, and the current-source Sonic1 qualification boundary
remains separately open.
