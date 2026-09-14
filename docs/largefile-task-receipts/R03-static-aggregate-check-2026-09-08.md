# R03 static aggregate Check verification — 2026-09-08

## Scope

This receipt records current-source static aggregate verification for the
large-file roadmap work. It is development evidence from an ARM64 disposable
container, not certified Linux x86-64 Release, sanitizer, or 32 GiB runtime
qualification evidence.

- Source: `<repository-root>`
- Branch: `largefile-roadmap-qualification`
- Source revision: `41cde8160286813f0f98e109c1450e40ff4117fb`
- Build directory: `/tmp/clamav-largefile-static-build` inside the container
- Build shape: `CMAKE_BUILD_TYPE=Debug`, `ENABLE_STATIC_LIB=ON`,
  `ENABLE_SHARED_LIB=OFF`
- Execution image: `clamav-largefile-local-toolchain2:latest`
- Architecture: ARM64 development container

The container received the missing development packages only inside the
disposable container: `libssl-dev`, `zlib1g-dev`, `libjson-c-dev`,
`libpcre2-dev`, `libxml2-dev`, `libcurl4-openssl-dev`, `libmilter-dev`, and
`check` with its required subunit packages. No host installation was used.

## Commands and results

The aggregate test executable was rebuilt from the canonical checkout:

```text
cmake --build . --target check_clamav -j2
[100%] Built target check_clamav
```

The suite was run with process isolation and an explicit 120-second Check
budget. `T=120` applies to the large `cl_scan_api` test case and
`CK_DEFAULT_TIMEOUT=120` applies to other test cases whose timeout is not set
in source:

```text
VERSION=1.5.3-largefile-devel
SOURCE=/src
BUILD=/tmp/clamav-largefile-static-build
TMP=/tmp
CVD_CERTS_DIR=/src/unit_tests/input/signing/verify
CHECK_CLAMAV=/tmp/clamav-largefile-static-build/unit_tests/check_clamav
CLAMD=/tmp/clamav-largefile-static-build/clamd/clamd
CLAMDSCAN=/tmp/clamav-largefile-static-build/clamdscan/clamdscan
CLAMSCAN=/tmp/clamav-largefile-static-build/clamscan/clamscan
CK_FORK=yes
T=120
CK_DEFAULT_TIMEOUT=120
/tmp/clamav-largefile-static-build/unit_tests/check_clamav
```

Results:

- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_scan_api`: 836 checks, 0 failures,
  0 errors.
- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=mhtml` with `CK_DEFAULT_TIMEOUT=120`:
  5 checks, 0 failures, 0 errors.
- Full aggregate suite: 2,836 checks, 0 failures, 0 errors.

An initial full run using Check's compile-time default timeout reported eight
timeouts in the 64–65 MiB streaming MBOX/MHTML cases but no assertion
failures. Repeating those groups with the explicit 120-second development
budget completed cleanly. The `traverse_to: Failed open payload` diagnostic
appeared during the normal corpus traversal; it did not produce a Check error
or failure in the passing run.

## Artifact hashes

```text
de03ab3a0037b68127ceaba7a7d5f26c821452da449ef16bbb752ab326670362  unit_tests/check_clamav
9b82dbf4f5d10c40e4a31d83ff5c8a3d6ebb0da20b5b7473ebf2f88668cf8fc6  CMakeCache.txt
e9649d9d3416df7802567063f88d8ff181795ed4e2bab827134c1707375df38c  unit_tests/input/clamav.hdb
```

No repository source files were changed for this verification slice. The
remaining qualification gates are unchanged: certified x86-64 Release and
sanitizer evidence, full-size corpus evidence, privileged fanotify evidence,
and production-canary evidence.
