# R03 local application-target probe — 2026-09-17

## Scope

This is a build-readiness probe for the canonical current checkout on
`largefile-roadmap-qualification`. It does not promote a build, capability, or
qualification result.

## Environment

- Source: `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- HEAD: `6312634ec24539dc6087a76df401a81b8e9aca7c`
- Existing image: `clamav-largefile-local-toolchain2:latest`
- Image ID observed: `3113a9a07ae4`
- Existing out-of-tree build container: `clamav-current-build-20260911`
- Container source mount: current checkout at `/src`
- No package installation, image pull, source upload, or source-tree mutation

## Commands and results

1. Started the existing container and inspected its generated build metadata.
   The prior cache had `ENABLE_LIBCLAMAV_ONLY=ON`, so it did not generate an
   application target even though `ENABLE_CLAMONACC=ON` was present.
2. Reconfigured `/tmp/clamav-current-build` against `/src` with the existing
   image dependencies. The library-only configuration completed successfully
   (exit `0`) and reported CMake 3.25.1, Clang 16.0.6, Cargo/Rustc 1.97.1,
   Libcheck, JSON-C, OpenSSL runtime headers, and PCRE2.
3. Reconfigured with
   `-DENABLE_LIBCLAMAV_ONLY=OFF -DENABLE_APP=ON -DENABLE_CLAMONACC=ON`.
   Configuration stopped with exit `1` because CMake could not find the curl
   development pair (`CURL_INCLUDE_DIR` and `CURL_LIBRARY`). The image has a
   runtime `libcurl.so.4` but no curl headers, so no application target was
   generated.
4. A separate compile-only `thread.c` probe was attempted with a temporary
   type-only curl header. It was intentionally not treated as a build: the
   image's incomplete OpenSSL development headers stopped preprocessing at
   `openssl/opensslconf.h` (exit `1`). The temporary stub was removed.
5. The existing container was stopped after the probe.

## Interpretation

The current on-access source was not rejected by a linked compile; the
available local image cannot perform that compile because its application
development dependency set is incomplete. Sonic1 remains short of the
roadmap's 68-GiB disk-backed temporary-space prerequisite (57,165,434,880
bytes free at the latest read-only check). A certified current-source Linux
x86-64 application build therefore remains pending; no stale binary was used
as a substitute.

## Next action

Use an authorized runner or existing image containing curl/OpenSSL development
headers and libraries, then reconfigure from the current source with
`ENABLE_LIBCLAMAV_ONLY=OFF` before compiling `clamonacc` and the remaining
application targets. Do not install or disable required dependencies merely to
make this probe pass.

## Existing Rust 1.97 container recheck

The pre-existing `rust:1.97-bookworm` image reports OpenSSL 3.0.20 and
libcurl 7.88.1 through `pkg-config`, so it was tested as an offline
top-level Rust-build alternative. The command

`docker run --rm -v "$PWD":/src -w /src rust:1.97-bookworm cargo test --offline -p clamav_rust --no-run --target-dir /tmp/clamav-rust-target-current-linux --message-format=short`

exited `101` before compilation because the pinned Git dependency
`clam-sigutil` is not present in that image's offline Cargo cache. No package,
source, or host installation was performed, and no network fetch was used.
