# R07 — Sonic1 format-8 bytecode compiler audit

Date: 2026-09-19
Task ID / parent milestone: `R07` / independent format-8 prerequisite

## Evidence identity

- Host: `sonic1`, login profile `sonic1-camera-key`
- Container: `clamav-current-7f3458c4`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Image: `clamav-32gb:dev-current`
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Build: `/tmp/clamav-7f3458c4-build`

## Availability check

The current Sonic1 container contains the in-tree runner:

```text
/tmp/clamav-7f3458c4-build/clambc/clambc
```

The following external compiler/toolchain paths are absent:

```text
/usr/bin/clambc
/usr/bin/llvm-as
/usr/bin/llvm-ld
/usr/bin/llc
```

The `ls` probe exited `2` solely because those external paths were absent; it
also confirmed the in-tree runner exists. No compiler, artifact, or network
dependency was installed or downloaded.

## Boundary and blocker

The in-tree runner and existing legacy/synthetic fixtures cannot satisfy the
roadmap requirement for an independently compiled format-8 fixture exercising
v2 globals, cross-4-GiB read/seek/search, late offsets, and both interpreter and
JIT execution. The exact missing dependency is an authorized compatible
format-8 bytecode compiler or a retained independently compiled format-8
fixture. R07 remains blocked by that external dependency; no qualification
claim is made.

State: `blocked-by-external-compiler`; release readiness remains blocked.
