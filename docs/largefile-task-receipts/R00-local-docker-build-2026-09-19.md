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

## Current-source recheck — 2026-09-19

At branch HEAD `5170d7f0`, a fresh disposable configure used the same
`clamav-largefile-local-toolchain2:latest` image with the current source
mounted read-only:

```text
docker run --rm -v <canonical-source>:/src:ro -v <disposable-build>:/build \
  -w /src clamav-largefile-local-toolchain2:latest \
  bash -lc 'cmake -S /src -B /build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DENABLE_TESTS=OFF -DENABLE_APP=ON -DENABLE_CLAMONACC=OFF \
    -DENABLE_MILTER=OFF -DENABLE_UNRAR=OFF -DENABLE_JSON_SHARED=ON'
```

The C/C++ compiler checks passed, but configuration stopped in
`cmake/FindRust.cmake`: `Cargo 1.97 or newer is required` and the image has no
`cargo`. The image also lacks the Git executable. This recheck therefore did
not reach JSON-C detection; the earlier JSON-C and offline `clam-sigutil`
failures remain valid independent blockers from the other retained probes.
No host software was installed, no repository files were mounted writable, no
remote state changed, and no usage reset was used.

## MCP-SSH current-source staging recheck — 2026-09-19

Using the administrator-provided `sonic1` host and `sonic1-camera-key` profile,
the durable transfer list was inspected before attempting any new transfer.
An upload of the current immutable archive (62,730,240 bytes,
SHA-256 `2c6c32a236e87a2be3be6e8ae22a1b336bc7d944af603c18e7313065ffabd12e`) to
a new `/tmp` destination was denied before writing with the authoritative
reason `file_write_limit_exceeded`. The existing remote checkout remains the
stale, dirty tree documented in the earlier Sonic1 receipt. Per MCP-SSH
continuation policy, no alternate destination or untracked copy was attempted.
