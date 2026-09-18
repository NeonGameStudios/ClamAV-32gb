# Task receipt: R03 local container configure probe — 2026-09-16

## Scope

This receipt records a non-installing, source-read-only ARM64 container
configure probe. It is a compile-environment diagnostic, not certified
Linux x86-64 qualification evidence.

## Identity and commands

- Source: `/Volumes/512gbNVME/github-external/ClamAV-32gb`, mounted read-only;
- image: `clamav-largefile-local-toolchain2:latest`;
- container architecture: `aarch64`;
- build directory: `/private/tmp/clamav-local-current-20260916-build`, mounted
  separately from the source;
- CMake/Rust tools available: CMake 3.25.1, Clang 16.0.6, Cargo/Rustc 1.97.1;
- configuration requested `RelWithDebInfo`, `ENABLE_CLAMONACC=ON`,
  `ENABLE_LARGE_FILE_DEFAULTS=OFF`, `ENABLE_TESTS=OFF`, and
  `ENABLE_SYSTEMD=OFF`.

## Results

- Configure with tests enabled — exit 1: `Libcheck` development headers and
  library were unavailable;
- configure with tests disabled — exit 1: `JSONC` development headers and
  library were unavailable after the Libcheck gate was bypassed;
- no package installation, source mutation, qualification configuration, or
  release label change was performed.

## Decision

The existing local image is useful for Rust and tool-level checks but cannot
configure the full application because its C development dependencies are
incomplete. The missing dependencies are an environment prerequisite, not a
source failure. The required x86-64 current-source build remains blocked on
an authorized runner and complete dependency/toolchain admission.

State: `environment-diagnostic; non-installing; qualification-pending`.
