# R03 Sonic1 clean v15 C ASan/UBSan exact-edge run — 2026-09-27

Task ID / parent milestone: R03 — certified build and reusable runner; focused sanitizer evidence only.

Starting Git commit: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d` on `largefile-roadmap-qualification`, with a dirty working tree. The tested source was frozen as a deterministic Gitless package; neither HEAD alone nor a later working-tree state is interchangeable with it.

## Source and runner identity

- Source manifest: 1,711 entries, SHA-256 `e5b0d36e0ac086aed6c0d9fe7037ef0c3ba1fb9fd6f2b3ac38a14891c4e4b04f`. A separate remote regeneration from the clean extraction reproduced this hash.
- Deterministic source package: 18,375,282 bytes, SHA-256 `45d1e6e67647e5fb68a9c6e60db9d4331392af1b2725416aff978db74d56369c`; a local independent repeat archive was byte-identical. Durable MCP-SSH transfer `transfer_78bfd4d3efcd4ecc9319ed16ee67748d` committed it to `/qualification/source-qual-20260926-v15-e5b0d36e.tar.gz`. Remote SHA-256 was rechecked after testing.
- Clean extracted source: `/qualification/src-v15-e5b0d36e`; clean build: `/qualification/build-v15-e5b0d36e-asan`. The extracted source guards passed before the build. The build cache records both `CLAMAV_SOURCE_COMMIT` and `CLAMAV_SOURCE_MANIFEST_SHA256` as the manifest hash above.
- Host/profile: `sonic1` / `sonic1-camera-key`; container ID `c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`; image ID `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Build cache SHA-256 `0b59c0200587d67eec292fceaedcef678c376bca2eb22c086d1897e3db3a315d`; exact test executable `unit_tests/check_clamav` SHA-256 `5ec7d7f9eebfb5bdaf4dc34c9ec24077721ce2c12f230a67576d6d61bbfbd850`.
- C and C++ compile flags included `-fsanitize=address,undefined -fno-omit-frame-pointer`; executable/shared/module link flags included `-fsanitize=address,undefined`; `ENABLE_WERROR=ON` and `ENABLE_LARGE_FILE_QUALIFICATION_TEST=ON`. UnRAR and milter were configured on; systemd is unavailable in this container and bytecode JIT remains unqualified. Cargo was forced offline against the pre-existing `/build/cargo` cache. No software was installed.

## Sonic1 run

- Fresh sanitizer build job `job_cf1a70aeb27b4ce99990b4407de90597` exited 0 after 485 seconds.
- Non-exact CTest job `job_53a0d2fcbbb14017bebb87c025322558` exited 0: 31/31 tests passed in 413.61 seconds. It includes `libclamav` (158.26 seconds), `libclamav_rust` (92.08 seconds), `clamscan`, `clamd`, milter, freshclam, sigtool, source guards, and evidence-check controls.
- The exact fixture was checked immediately before the edge run: `/dev/shm/clamav32gb-edge-20260926.bin`, size 34,359,738,368 bytes, 67,108,864 allocated 512-byte blocks. The test itself checks `SEEK_HOLE`, the final 16-byte `EDGE-LATE-MARKER`, and unchanged fixture metadata after scanning.
- Exact-edge CTest job `job_2ca9082416034e36be26834c114f8549` exited 0: `largefile_library_exact_32g` passed in 652.29 seconds, with zero failed tests and empty job stderr. The test asserts exact late-marker detection and report/budget values through `cl_scanfile_ex2`, `cl_scandesc_ex2`, and `cl_scanmap_ex2`. It uses a separate custom signature, not production CVDs.
- A live Docker sample during the exact run showed 37.89 GiB / 62.21 GiB container memory and 99.97% CPU. These are point-in-time observations, not peak-RSS proof. `/proc/swaps` was empty both during and after the run. The fixture remained fully allocated after testing (same size and block count).

## Qualification boundary and next actions

This is clean-current-source Linux x86-64 C ASan/UBSan build and CTest evidence, including a fully allocated exact-32-GiB library edge. It is **not** complete Rust address-instrumentation proof. The container's `rustup toolchain list` exposed only `stable-x86_64-unknown-linux-gnu`; the Rust CTest build used `-C link-arg=-fsanitize=address,undefined`, which links runtimes but does not itself instrument Rust code. The runtime gate requires a nightly toolchain, `-Zsanitizer=address`, and an instrumented Rust archive. No nightly toolchain was installed or downloaded in this run.

This run also does not satisfy the final disk-backed admission contract. `/qualification` had 56,798,744 KiB available (about 54 GiB) during testing, below the required 68 GiB, and the host root filesystem had only 298,008 KiB free. The volume group reported 498.82 GiB unallocated, but no host-volume change was made. The RAM-backed exact library test is not a substitute for final service/production-CVD, parser/ingress, capability-specific, or resource-phase acceptance. Systemd and bytecode JIT qualifications remain open. Do not promote readiness or capability rows from this receipt alone.

State: `current-source C ASan/UBSan suite and exact library edge passed; Rust sanitizer, disk-backed admission, and release matrix pending`.
