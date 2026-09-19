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

An ARM64 Linux container attempt was also made with direct Rust 1.97.1
binaries and network access disabled. Cargo first resolved the repository
workspace and stopped on the absent `clam-sigutil` Git source. Copying each
standalone crate outside the workspace then stopped on missing offline crates
(`bytes` for OneNote and `bitflags` for LHA/LZH). No Linux pass is claimed.

## Limits

These are standalone crate results only. The full `clamav_rust` crate still
cannot run offline because the pinned `clam-sigutil` Git dependency is absent,
and the native ClamAV configure remains blocked on JSON-C in the retained
Docker image. Current C ABI linkage, production databases, sanitizer parity,
certified Linux x86-64, and final release qualification remain open.
