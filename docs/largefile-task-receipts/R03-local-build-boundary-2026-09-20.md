# R03 local build boundary — 2026-09-20

## Scope

Revalidate the current qualification checkout's locally available build paths
without installing software or weakening required Rust/CMake features.

## Current-source evidence

- Checkout: branch `largefile-roadmap-qualification`, revision `02165f0b`.
- `cargo test --offline --manifest-path
  libclamav_rust/onenote_parser/Cargo.toml` passed **85 unit tests**, **6
  integration tests**, and **1 ignored doctest** against the current vendored
  OneNote parser.
- `CARGO_TARGET_DIR=/private/tmp/clamav-rust-current-target cargo check
  --offline --locked -p clamav_rust` reached the current crate build graph but
  failed in `openssl-sys` because the host has no discoverable OpenSSL
  development installation or `pkg-config` (`exit 101`).
- The existing `clamav-largefile-local-toolchain2:latest` Docker image has
  CMake, Clang, and Make, but no Cargo, JSON-C development package, or Check
  package. A read-only CMake configure therefore stops at the required Cargo
  1.97 check before producing a build (`exit 1`).

No host software was installed, no repository dependency was changed, and no
feature was disabled to obtain a partial pass.

## Boundary and next action

This is a build-readiness blocker, not release qualification. The next R03
action requires an already-authorized runner or an existing image/toolchain
containing Cargo 1.97+, OpenSSL development headers, JSON-C, Check, and the
required optional libraries. Sonic1 current-source qualification also remains
blocked by the previously recorded source-staging and stale-container
boundaries.
