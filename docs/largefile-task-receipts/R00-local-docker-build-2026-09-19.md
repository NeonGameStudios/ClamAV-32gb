# Task receipt: R00 local Docker native-build probe — 2026-09-19

## Scope

Determine whether the current source can be configured and built in the
existing local Linux Docker toolchain without installing host software or
using MCP-SSH.

## Environment

- Image: `clamav-largefile-local-toolchain2:latest`
- Container architecture: `aarch64`
- Compiler: Clang 16.0.6
- CMake: 3.25.1
- Rust: 1.97.1
- Source: branch `largefile-roadmap-qualification`, commit `05d2bb3e`
- Build directory: disposable container `/tmp/clamav-build`

## Evidence

The CMake configure command used the mounted current source and pre-copied
OpenSSL, zlib, BZip2, LibXml2, and PCRE2 headers/libraries. It successfully
detected the C/C++ compiler, Rust toolchain, Threads, OpenSSL 3.0.20, zlib,
BZip2, LibXml2, PCRE2, and Iconv.

Configuration stopped at the required JSON-C dependency:

```text
Could NOT find JSONC (missing: JSONC_LIBRARIES JSONC_INCLUDE_DIRS)
```

Both retained local ClamAV toolchain images were checked. Neither contains
`libjson-c`, JSON-C headers, or a usable JSON-C development package. The
container's copied `pkg-config` binary also cannot start because its
`libpkgconf.so.3` runtime library is absent.

An independent direct-binary Rust check was also attempted with network access
disabled and the image's pinned Rust 1.97 toolchain. Cargo stopped before
compilation because the pinned `clam-sigutil` Git dependency is not present in
the image's offline cache:

```text
can't checkout from 'https://github.com/Cisco-Talos/clamav-signature-util'
you are in the offline mode (--offline)
```

## State

`blocked-external-prerequisite`: the existing container image needs a
compatible JSON-C development package, a working `pkg-config` runtime, and
the pinned `clam-sigutil` source (or an authorized Linux build runner that
already provides them). No host software was installed, no usage reset was
used, no remote state was changed, and no GitHub workflow was triggered.
Native C/Rust test execution, Release/ASan/UBSan builds, production
databases, and final qualification remain open.
