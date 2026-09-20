# Sonic1 sanitizer toolchain blocker — 2026-09-20

## Scope

This receipt records the R03 sanitizer preflight after the exact current-source
Release build and 31/31 Release CTest pass. No sanitizer build was started
because the existing authorized runner lacks the required installed toolchain.
No software was installed or downloaded, and no capability was promoted.

## Identity

- Host: `sonic1`
- Login profile: `sonic1-camera-key`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Source manifest: `f7be88d8961ee5e5546e5fbcf44374a70c083deccbb34ba867547a9cd6aacf8f`
- Release baseline: `aa6c0077130c9f7aefd8d366aa9a689ffc6c87fe`

## Preflight result

```text
rustup toolchain list
stable-x86_64-unknown-linux-gnu (default)
1.97-x86_64-unknown-linux-gnu (active)

clang --version
exit 127: executable file not found in $PATH

clang++ --version
exit 127: executable file not found in $PATH
```

The roadmap and `largefile_runtime_gate.sh` require a C ASan/UBSan build and
Rust address instrumentation using a nightly Rust toolchain. The installed
container has neither the required C compiler frontend nor a nightly Rust
toolchain, so a valid sanitizer evidence run cannot be produced on this
runner without an external toolchain change.

## Existing-image audit follow-up

A read-only Docker inventory and executable probe were repeated on 2026-09-20
UTC. The available images included `clamav-32gb:dev-current`,
`clamav-32gb:test-tools-742a8a4`, `mtgo-ai-player2:local-native-fix`,
`mtgo-ai-player2:local-native`, `ghcr.io/jidicula/clang-format:16`, and
`rust:1.97-bookworm`. Probing the already-present images that appeared
potentially relevant with `docker run --rm --entrypoint clang ... --version`
or `--entrypoint rustup ... toolchain list` returned exit 127 (executable not
found) for all four probes. No image pull, package installation, or source
mutation occurred. The inventory therefore does not provide an existing
replacement for the missing C compiler frontend or Rust nightly toolchain.

The same read-only host recheck measured 37,977,477,120 bytes available on
the disk-backed root filesystem and 63,750,356,992 bytes available memory;
the root free space remains below the roadmap's approximately 68 GB
disk-backed staging requirement, while memory remains above the 48 GiB
minimum. These values do not relax the sanitizer or full-size qualification
requirements.

## Disposition

R03 Release integration is complete for this runner, but R03 as a whole and
release readiness remain open. This is an external toolchain blocker, not a
source or test failure. Do not substitute a C-only sanitizer run for the
required Rust-instrumented evidence and do not install/download toolchains
under the current no-install directive.
