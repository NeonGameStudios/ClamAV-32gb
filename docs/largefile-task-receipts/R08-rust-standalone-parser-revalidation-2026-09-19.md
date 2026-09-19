# Task receipt: R08 standalone Rust parser revalidation — 2026-09-19

## Scope

Revalidate the vendored OneNote and LHA/LZH parser crates independently while
the full ClamAV C/Rust build remains unavailable. This is development evidence
for the bounded parser implementations, not a claim of C ABI or release
qualification.

## Commands and results

Both commands used the current checkout, Cargo lockfiles, an offline cache, and
disposable `/tmp` target directories:

```text
CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=/tmp/clamav-onenote-target \
  cargo test --locked --manifest-path libclamav_rust/onenote_parser/Cargo.toml
  84 unit tests passed; 5 integration tests passed; 1 doc test ignored

CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=/tmp/clamav-delharc-target \
  cargo test --locked --manifest-path libclamav_rust/delharc/Cargo.toml
  13 unit tests passed; 1 doc test passed; 1 doc test ignored
```

The OneNote integration suite includes the logical-input-over-former-cap and
short-read reader cases. The LHA/LZH suite includes cumulative header
allocation admission and decoder coverage.

## Current-checkout offline rerun

The same two commands were rerun against the current checkout after the latest
roadmap changes, using fresh disposable target directories outside the
repository so Cargo could not create an in-repository build lock:

```text
CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=/private/tmp/clamav-onenote-offline-current \
  cargo test --locked --manifest-path libclamav_rust/onenote_parser/Cargo.toml
  84 unit tests passed; 5 integration tests passed; 1 doc test ignored

CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=/private/tmp/clamav-delharc-offline-current \
  cargo test --locked --manifest-path libclamav_rust/delharc/Cargo.toml
  13 unit tests passed; 1 doc test passed; 1 doc test ignored
```

Both offline reruns passed. The OneNote run emitted existing compiler warnings
only; no source or generated files were written into the repository.

## Full Rust consumer recheck

The complete `libclamav_rust` consumer was then attempted with the local Cargo
cache and a fresh disposable target directory:

```text
CARGO_NET_OFFLINE=true CARGO_HOME=/Users/claude/.cargo \
  CARGO_TARGET_DIR=/private/tmp/clamav-rust-full-current \
  cargo test --locked --manifest-path libclamav_rust/Cargo.toml
```

Cargo resolved the pinned `clam-sigutil` 1.2.4 Git source from the local cache
and compiled the dependency graph until `openssl-sys v0.9.117`. The build then
stopped because the macOS worktree has no discoverable OpenSSL development
headers/libraries or `pkg-config`; the available `/usr/bin/openssl` is
LibreSSL and does not provide the required development installation. This
removes the previously reported local `clam-sigutil` cache miss as the current
host-side blocker, but does not establish a full Rust or C/Rust application
build. No software or dependency was installed.

An ARM64 Linux container attempt was also made with direct Rust 1.97.1
binaries and network access disabled. Cargo first resolved the repository
workspace and stopped on the absent `clam-sigutil` Git source. Copying each
standalone crate outside the workspace then stopped on missing offline crates
(`bytes` for OneNote and `bitflags` for LHA/LZH). No Linux pass is claimed.

## Exact-toolchain Linux consumer recheck

The locally cached ARM64 `rust:1.97-bookworm` image was rerun with its
installed `1.97.1-aarch64-unknown-linux-gnu` toolchain selected explicitly,
avoiding the earlier rustup alias/download boundary. With the current source
read-only, the existing Cargo cache read-only, and a disposable target outside
the repository, the complete consumer library compiled offline:

```text
CARGO_NET_OFFLINE=true CARGO_HOME=/cargo-cache \
  RUSTUP_TOOLCHAIN=1.97.1-aarch64-unknown-linux-gnu \
  CARGO_TARGET_DIR=/build-target \
  cargo build --locked --manifest-path libclamav_rust/Cargo.toml --lib
  Finished `dev` profile in 2m 22s; libclamav_rust.a was produced
```

The build included the pinned `clam-sigutil` 1.2.4 source and OpenSSL-backed
consumer code. The same environment's standalone `cargo test` compiled the
full crate and dependencies, then failed only while linking the test binary:
the native ClamAV C ABI hooks (`cli_mark_scan_incomplete`, `cli_versig`, the
logging/time-limit functions, and related symbols) are supplied by the C
application build and are not present in a standalone Cargo test invocation.
This confirms Linux Rust source compilation while leaving C/Rust integration
linkage, native CMake, runtime, sanitizer, certified x86-64, and release
qualification open.

## Limits

These are standalone crate results plus a successful exact-toolchain Linux
consumer library build and a test-link boundary. The full native C/Rust
application remains unverified because the retained CMake Docker image lacks
Cargo and JSON-C prerequisites, while the macOS host lacks the required
OpenSSL development environment. Current C ABI linkage, production databases,
sanitizer parity, certified Linux x86-64, and final release qualification
remain open.
