# R08 LHA/LZH parser revalidation — 2026-09-17

## Scope

Revalidate the vendored `delharc` LHA/LZH parser independently while the
top-level `clamav_rust` integration build is unavailable on this macOS host.
The scanner-facing path remains bounded by the caller's fmap, header-allocation
limit, scan limits, temporary spool budget, declared member size, deadline, and
CRC checks; this receipt does not promote the LHA/LZH capability.

## Verification

- `cargo test --manifest-path libclamav_rust/delharc/Cargo.toml
  --target-dir /private/tmp/clamav-delharc-target-current` — exit 0.
- 13 unit tests passed, including LHA v1/v2 decoding and cumulative header
  allocation-limit rejection.
- 1 doctest passed; 2 doctests were intentionally ignored by the vendored
  crate.

## Qualification boundary

This is isolated parser development evidence only. It is not current-source
top-level Rust integration evidence, certified Linux x86-64 evidence, a
full-size/materialized fixture, sanitizer evidence, or capability-specific
release qualification. The top-level build remains blocked by the local
absence of discoverable OpenSSL development files and `pkg-config`.

State: `development-verified; integration-and-qualification-open`
