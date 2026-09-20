# R03 Sonic1 CMake manifest-timeout boundary — 2026-09-20

## Scope

Bounded revalidation of the pre-existing Sonic1 native/Rust build environment
using MCP-SSH profile `sonic1-camera-key`. This is diagnostic evidence only;
the mounted source is stale and dirty, so it cannot qualify the current
checkout.

## Prerequisites and source identity

- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- `/src` is a read/write bind of `/tmp/clamav-32gb-current-20260915`.
- CMake captured source revision
  `08b3ab820e40ac8bd307b0c78c03c94884f1b`, not the current qualification
  checkout. The source tree is extensively dirty.
- The image has CMake 3.25.1, GCC 12.2, JSON-C 0.16, Check 0.15.2, and
  stable Rust/Cargo/Rustc 1.97.1.

## Probe and observed boundary

The typed command was:

```text
cmake -S /src -B /tmp/clamav-cmake-probe-20260920 \
  -DCMAKE_BUILD_TYPE=Release -DRUSTUP_TOOLCHAIN=stable
```

The MCP-SSH Docker execution wrapper returned its fixed 20-second transport
timeout while the CMake process continued remotely. Polling the same process
showed that it spent several minutes hashing the retained
`r11-materialized-20260916/32g-zip-edge.bin` fixture as part of the immutable
source manifest. The completed manifest contains 22,511 entries and is
3,534,296 bytes.

The disposable build directory contains a CMake cache and compiler probe logs,
with `CMAKE_C_COMPILER=/usr/bin/cc`, `CMAKE_CXX_COMPILER=/usr/bin/c++`,
`CMAKE_MAKE_PROGRAM=/usr/bin/gmake`, and `RUSTUP_TOOLCHAIN=stable`. It has no
`Makefile` or generated target graph. The second bounded rerun reached the
same manifest phase and then disappeared from the container before dependency
discovery; the timed-out MCP call did not retain a reliable CMake exit status
or stderr. This is an execution-lifecycle boundary, not evidence that the
complete Sonic1 image lacks the required dependencies.

## State and next action

State: **blocked for this probe; R03 current-source qualification remains
open**.

No software was installed, no source was transferred, no required feature was
disabled, no reset credit was used, and no capability status changed. The next
useful action is to run the current immutable source candidate through an
authorized runner or an administrator-configured async validation profile that
can retain output beyond the MCP Docker execution timeout. Do not treat this
stale checkout or its partial CMake cache as build evidence.
