# R03/R05 Sonic1 current-source Release exact-32-GiB library qualification — 2026-10-02

## Candidate and runner

- Repository: `ClamAV-32gb`; branch: `largefile-roadmap-qualification`.
- Candidate HEAD: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`; the packaged
  working tree was dirty and source-bound separately.
- Git-less source-content manifest SHA-256:
  `b7e4fefa1a661aa8bd9dc76ac499073ce45c5b2d03451d70c51692672338c144`.
- Deterministic package SHA-256:
  `71ee62d2c1c2a5bb206c668f0f5e25f5f0818c5db2a75f04679be0266ead7645`;
  durable package transfer `transfer_52dc48d4d7a64e03bdf83d8110505e69`.
  Sidecar transfer:
  `transfer_b6921709798e4b83b92e3cdb8b8b1d96`.
- Host/profile: `sonic1` / `sonic1-camera-key`. Host preflight: Linux
  x86_64, 12 CPUs, 65,234,456 KiB RAM, at least 48 GiB available, no swap,
  and at least 108 GiB free on the qualification LV before build.
- Image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
  The original runner is container
  `d2b2c469e1c7e07a18e2955fbce5fd598c9a39a842f4a6ab03ba9973be17fd24`.
  A network-isolated runner, `450e8d8f297ffb0d8ace2900b2802bfb2a6f47b63ea40d1e48d0168fd7a41a6c`,
  used that same image and explicitly mounted the qualification LV and
  Sonic1's 40-GB tmpfs at `/ram`.

## Release build and tests

- Out-of-tree Release CMake configure and build both exited zero from the
  extracted, manifest-verified package. Required app, clamonacc, milter,
  JSON-shared, static/shared library, UnRAR, tests, large-file defaults, and
  exact qualification-test options were enabled. Bytecode runtime was
  interpreter; systemd/man pages/doxygen were disabled.
- Non-edge Release CTest ran 31 of 32 tests successfully; its sole failure was
  `libclamav_rust` attempting to sync Rustup through the container's
  non-writable default home before entering tests. No toolchain update
  completed. Rerunning only that test with the already-present Rust 1.97.1
  toolchain and copied Cargo cache, with Cargo offline, passed 1/1 in 12.70 s.
  The other 31 passed, including `libclamav`, CLI, daemon, milter and
  release-control tests. This is a combined 32/32 across the two retained
  runs, not a single rerun of the entire matrix.

## Fully materialized exact-32-GiB RAM fixture

- Fixture: `/ram/edge-stable.bin`, exactly 34,359,738,368 bytes; all
  67,108,864 512-byte blocks allocated; first hole exactly at EOF.
- SHA-256:
  `98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
- The expected 16-byte literal `EDGE-LATE-MARKER` was independently found
  once at offset 34,359,738,352 (EOF−16).
- `tools/largefile_binary_literal_oracle.py --require-materialized`
  independently read all 34,359,738,368 bytes and passed: stable metadata,
  full-file hash, exact allocation, no earlier hole and unique exact-offset
  marker all matched.

## Exact library result

The dedicated CTest `largefile_library_exact_32g` passed **1/1** in
329.62 seconds on the manifest-bound Release binary. Its assertions cover
`cl_scanfile_ex2`, `cl_scandesc_ex2`, and `cl_scanmap_ex2`; for each, it
requires `CL_VIRUS`, strong-indicator verdict, exact
`LargeFile.Library.32G.UNOFFICIAL` alert and EOF−16 offset, detection-
terminated completion, root size, matcher/logical progress through the exact
tail, binary file type and the configured large-file limits. It does not
qualify parser families, CLI/service ingress, or production signatures.

At the end of the run Sonic1 reported 30.8 GB available memory and zero swap.
Sampled scanner RSS stayed below 104 MiB; the scan traversed the full fixture
three times. Logs are retained on Sonic1 at
`/tmp/clamav-qualification-disk-lv-v1/qual32g-mur2oy8d-5798545b-run/logs/`
(`ctest-release-nonedge.log`, `ctest-release-rust-retry.log`,
`ctest-release-exact-32g.log`, and `configure-release.log`).

## Sanitizer build and remaining work

A separate C/C++ ASan/UBSan configuration from the same package completed
successfully with the same feature set and source-manifest digest. It uses
`-fsanitize=address,undefined -fno-omit-frame-pointer` for C/C++ compile and
link. Managed build job `job_59f6af84d7d9488a98531beffd2a66a0` exited zero;
its log is `build-asan.log`. The ASan/UBSan non-edge CTest suite passed
**32/32** in 414.11 seconds (managed job
`job_f491c6488b37476a989b9f4afc37cc4e`). The exact-edge test then passed
**1/1** in 641.28 seconds (managed job
`job_f30edf5ab0a246cca627b582e030b656`), with
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. There were no sanitizer
diagnostics, and the CTest process exited zero. The test exercised the same
three library APIs and exact EOF marker contract as the Release test on the
fully materialized RAM fixture. During execution the scanner RSS sample was
about 251-300 MiB; host available memory remained about 28 GiB and swap stayed
at zero. Rust was tested with the pinned stable toolchain but is not
Rust-address-instrumented by these C sanitizer flags. A separate tracked
post-scan `sha256sum` job (`job_427ae99954c54a71ac6aff3c919ae097`) read the
entire fixture and reproduced the pre-scan SHA-256 exactly:
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
The sanitizer logs are retained as `ctest-asan-nonedge.log` and
`ctest-asan-exact-32g.log` alongside the Release logs in the same run log
directory.

The roadmap remains open: full ZIP/parser-family vertical qualification,
all-ingress/service matrix, PCRE phase memory, queues/resources, fanotify,
production-CVD canary, capability-specific evidence and final readiness.
No capability row is promoted by this receipt. No software install, commit,
push, GitHub workflow action or usage reset was performed in this qualification
slice.

## Production-CVD prerequisite retry

After the previously documented CDN cool-down expired, the manifest-bound
Release `freshclam` was run once in a disposable bridge-network container as
UID 1000, with all capabilities dropped, no-new-privileges, read-only root,
read-only build/certificate mounts, and only this run's private evidence
directory writable. No host/system ClamAV database was mounted or modified.
FreshClam resolved `database.clamav.net`, completed TLS verification, learned
software version 1.4.6 and daily database version 28141, then received HTTP
403 for `daily.cvd`; Cloudflare Ray ID:
`a444f5a0ebd6b017-MIA`. It set the new FreshClam cooldown until after
`2026-10-03 16:07:20 UTC`. No signed production database was downloaded and no
production-CVD scan ran. Do not retry before that time; the canary remains
blocked pending an authorized current signed database source or CDN access
resolution. The diagnostic is retained at
`evidence/freshclam-retry-20261002-v2.log` on Sonic1.

State: **Release and C ASan/UBSan exact-32-GiB library API tests passed;
private production-CVD acquisition is externally blocked; overall
qualification incomplete.**
