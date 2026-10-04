# R06 local OneNote reader test receipt

Date: 2026-09-26

## Candidate identity

- Repository/branch: `ClamAV-32gb`, `largefile-roadmap-qualification`.
- Candidate HEAD: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`; working tree dirty.
- Source manifest SHA-256: `acd1fcc3deb563f21e315bf0d0c868e83b4a00d4ca932727ca22163fa5c65be7`.
- Tested component: `libclamav_rust/onenote_parser`.
- Cargo target output was isolated under `/private/tmp/clamav-continuation-20260926.NtMZ0g/cargo-target-onenote`.

## Test

Ran offline, without installing software:

```sh
CARGO_TARGET_DIR=/private/tmp/clamav-continuation-20260926.NtMZ0g/cargo-target-onenote \
  cargo test --offline --manifest-path libclamav_rust/onenote_parser/Cargo.toml
```

The parser crate compiled successfully. Results: 85 unit tests passed, 6
integration tests passed, 0 failed; one unrelated doctest was ignored. Cargo
reported existing unused/dead-code warnings but no compile or test errors.

## Scope and remaining qualification

This proves the standalone Rust parser crate and its reader-backed integration
tests work on the local host. It does not prove the ClamAV C/Rust FFI build,
sanitizer configuration, a fully materialized 32-GiB OneNote scan, or any
release capability. Those still require the coherent certified build and
fresh Sonic1 runtime evidence.

An offline `cargo test --manifest-path libclamav_rust/Cargo.toml` attempt
reached `openssl-sys` and stopped with exit 101 because no OpenSSL development
SDK or `pkg-config` is available locally. The Xcode SDK also has no OpenSSL
headers. Nothing was installed; this is not a Rust source-test failure. The
full wrapper/FFI test still needs the certified Sonic1 build environment.
