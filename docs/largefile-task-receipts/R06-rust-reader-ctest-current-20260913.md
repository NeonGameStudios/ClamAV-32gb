# R06/R08 Rust reader current-source CTest — 2026-09-13

## Scope

Run the repository's configured Rust test target against the current source
through both build variants. This exercises the Rust reader/parser and FFI
implementation families, including the reader-backed OneNote path and the
Rust utility/parser regressions registered by the project.

## Provenance

- Source root: `/src`, mounted from
  `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- Source manifest: `4ff6260cf89396c0d4a5c96c889b89558cab599e33c4b26976921ce629749efc`
- Release build: `/tmp/clamav-release-current-20260913`
- ASan/UBSan build: `/tmp/clamav-asan-current-20260912`
- CTest target: `libclamav_rust`
- Configured command: `cargo test --locked --target aarch64-unknown-linux-gnu --release`
- Certificate binding: `/src/unit_tests/input/signing/verify`
- Runner: existing disposable `rust:1.97-bookworm` ARM64 Linux container

## Results

| Build | CTest result |
| --- | ---: |
| Release | 1/1 passed |
| ASan/UBSan | 1/1 passed |

Both invocations exited successfully with zero failed tests. No sanitizer,
leak, undefined-behavior, or runtime-error diagnostics were emitted.

## Qualification boundary

This is current-source ARM64 development evidence only. It does not replace
the certified Linux x86-64 Release/sanitizer runs, exact/materialized 32-GiB
fixtures, production CVD/service evidence, resource/fanotify evidence, Sonic1
evidence, independent format-8 bytecode evidence, or final release
qualification. No capability status was promoted.
