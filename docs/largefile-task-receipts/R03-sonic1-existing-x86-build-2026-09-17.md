# R03 Sonic1 existing x86-64 build environment — 2026-09-17

## Scope

Read-only inspection of the already-running Sonic1 container after the local
application-target probe. This receipt establishes environment availability;
it is not current-source build or qualification evidence.

## Identity

- Host: `sonic1`, login profile `sonic1-camera-key`
- Container: `clamav-current-source-20260915`
- Container ID: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- `/src` bind: `/tmp/clamav-32gb-current-20260915`
- Known container source commit: `08b3ab820e40ac8bd307b0c78c03c94884f1b`
- Current checkout commit: `6312634ec24539dc6087a76df401a81b8e9aca7c`

## Read-only findings

- `/usr/include/x86_64-linux-gnu/curl/curl.h` exists.
- `/usr/include/x86_64-linux-gnu/openssl/opensslconf.h` exists.
- The existing CMake cache has `ENABLE_LIBCLAMAV_ONLY=OFF` and
  `ENABLE_CLAMONACC=ON`.
- The existing build tree exposes a `clamonacc` target and already contains a
  `clamonacc` executable plus a `scan/thread.c.o` object. Those artifacts are
  bound to the stale source tree and were not executed, copied, or promoted.

## Interpretation

Sonic1 has a usable x86-64 application-build environment. The current-source
qualification path remains blocked by two independent prerequisites: the
known stale `/src` bind cannot serve as current-source evidence, and the host
has only 57,165,434,880 bytes free on disk-backed `/tmp` versus the roadmap's
68-GiB admission requirement. The earlier client-local durable upload attempt
was rejected by MCP-SSH's authoritative `file_write_limit_exceeded` policy;
no alternate transfer workaround was attempted here.

## Next action

Obtain an authorized current-source delivery path or runner workspace, then
rebind/rebuild from the exact current checkout and retain fresh source/build
identity. Do not use the existing stale executable or object as a substitute.
