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

The asynchronous MCP-SSH command path was then used with job
`job_f1508bb8c8054e58b083f0302d0650d6`, an effective 1,200-second timeout, and
the same typed Docker command. It retained the actual exit status: **1**.
CMake completed compiler detection and source-manifest generation, then
reported `Rust tool \`cargo\` not found: Failed to determine version.` Direct
`cargo --version` reproduced the cause: rustup attempted to sync the pinned
`1.97` channel and could not create a file under `/home/clamdev/.rustup`.
`rustup run stable cargo --version` succeeded with Cargo 1.97.1, proving the
installed stable toolchain exists but the discovery environment was wrong.

The current checkout now applies `RUSTUP_SKIP_SELF_UPDATE=1` and the explicit
`RUSTUP_TOOLCHAIN` to CMake's Rust version probes, and applies the same
environment to the native-static-libs `rustc` probe. A read-only CMake smoke
against the existing local toolchain image found Cargo, Rustc, and Rustup all
at the expected versions before stopping at that image's known missing JSON-C
development files. The source guards pass.

An environment-injected recheck was then run through the same async MCP-SSH
path as job `job_3a95de06ebac4d1984785134eafa8082`, with
`RUSTUP_TOOLCHAIN=stable` and `RUSTUP_SKIP_SELF_UPDATE=1` supplied to the
container. It completed with exit **0**: CMake finished configuration and
generation in `/tmp/clamav-cmake-env-20260920`, finding Cargo/Rustc 1.97.1,
the native Rust link libraries, JSON-C, OpenSSL, ZLIB, BZip2, LibXml2, PCRE2,
Iconv, CURL, CURSES, Milter, and the compiler feature set. Systemd and TINFO
were absent but non-fatal for this configure. This recheck used the stale
dirty `/src` mount, so it verifies the Sonic1 image and the Rust discovery
environment rather than qualifying the current immutable source candidate.

The follow-on stale-source build smoke (`job_fc42136c8fd44a30b47b54b0705cf0b7`)
reached 92% before failing with exit **2** while linking the
`check_clamav` unit-test executable. Its retained stdout was capped and its
stderr stream was empty. Incremental isolation confirmed that the core
`clamav` target completed successfully (`job_63df5b28d35248729af730cd6235d503`)
and that the production binaries through `clamscan`, `clamd`, `clamonacc`,
and `clamav-milter` had already built. A serial all-target rerun and an
isolated `check_clamav` rerun reproduced the same link boundary; verbose mode
did not retain the final linker diagnostic. This is a stale-source image
diagnostic, not a current-source failure claim.

## State and next action

State: **implemented/development-verified for the Rust discovery slice; the
Sonic1 image reaches the production build and has a stale-source unit-test link
boundary; R03 current-source qualification remains open**.

No software was installed, no source was transferred, no required feature was
disabled, no reset credit was used, and no capability status changed. The next
useful action is to run the current immutable source candidate through the
complete Sonic1 image using the async command path, then address any genuine
native dependency or build failures. The stale-source smoke has now exposed a
unit-test link boundary after the production targets built; it remains
diagnostic until the current source candidate is transferred or otherwise
mounted. Do not treat the stale checkout or its partial CMake cache as
current-source qualification evidence.
