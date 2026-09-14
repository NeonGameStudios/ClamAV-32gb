# Task receipt: R03 current-source `clamav_rust` Cargo compile check

Task ID / parent milestone: `R03` / `R06-R09`

## Scope

Compile the current `clamav_rust` static-library package with the pinned
offline dependency graph, and probe its standalone Rust unit-test link. The
package is normally linked into the CMake-built ClamAV application; the
standalone test link is recorded separately because its native C symbols are
provided by that application link.

## Provenance

- host worktree: `/Volumes/512gbNVME/github-external/ClamAV-32gb`;
- branch: `largefile-roadmap-qualification`;
- source manifest: 1,697 entries;
- source manifest SHA-256: `ea89582cd812e7147eb7c5ac06f4c98e54c6103bbc801384dc0c8fb08eb0cbd2`;
- source mount: current worktree at `/src`;
- retained container: `clamav-current-rust-build-20260911`;
- Rust toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, `cargo 1.97.1 (c980f4866 2026-06-30)`;
- dependency resolution: Cargo `--offline`; no host software or dependency
  installation/download was performed.

## Results

Compile-only validation:

```text
docker exec -w /src clamav-current-rust-build-20260911 \
  cargo check --offline -p clamav_rust --lib
```

Exited 0. All C/Rust package code and build scripts compiled. Existing Rust
warnings remain (deprecated APIs and unused fields/imports); none was a
compile error.

Standalone unit-test link diagnostic:

```text
docker exec -w /src clamav-current-rust-build-20260911 \
  cargo test --offline -p clamav_rust --lib
```

Exited 101 at the linker stage. The test executable requires native ClamAV
symbols supplied by the CMake application link, including `cli_versig`,
`cli_versig2`, `cli_checktimelimit`, `cli_mark_scan_incomplete`, logging
callbacks, and matcher callbacks. No Rust compilation error or test assertion
failure occurred. The CMake-linked Check runner remains the authoritative
Rust/C integration test path and has already been exercised separately.

## Boundary and next action

This confirms package compilation but does not claim a standalone Cargo test
target or certified release qualification. A future CMake-linked Rust/C test
run should be used for executable assertions; do not add incomplete native
stubs merely to make this static-library package link in isolation.

No capability status was promoted. No usage reset, software installation,
branch/history/remote change, commit, push, or GitHub workflow action was
performed. The retained container was stopped after the checks.

State: development-verified (compile-only)
