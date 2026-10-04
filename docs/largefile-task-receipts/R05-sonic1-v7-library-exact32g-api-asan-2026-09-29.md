# R05 Sonic1 v7 C ASan/UBSan exact-32-GiB library API regression — 2026-09-29

This receipt adds a sanitized build and raw library API parity check to
`R05-sonic1-v7-library-exact32g-api-2026-09-29.md`. It does **not**
qualify the entire ingress matrix or the disk-spooling OneNote parser.

## Frozen source and build

The authorized runner was `sonic1` / `sonic1-camera-key`, pinned container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
and image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The already transferred and manifest-regenerated frozen v7 source package
has source-content manifest SHA-256
`72bb5de991f23098030c27f666578740b1ca74eaf0e7b3e1b9938735a70b2ebb`.
The sanitized CMake configuration used `RelWithDebInfo`, C/C++
`-fsanitize=address,undefined -fno-omit-frame-pointer`, both executable
and shared linker sanitizer flags, static and shared libraries,
large-file defaults, and the registered exact-edge test. The generated
cache embeds the exact v7 source manifest as both source identity fields.
Configure job `job_18697e6c49b24278a8e8d3f0b1a4aea6` and offline build
job `job_2cde2346d37a49d4993151edcb0348cf` exited 0. The initial
build's bounded output saturated on compiler warnings; a subsequent
no-op build reached 100% of targets with exit 0 and no stderr. The
sanitized `check_clamav`, `clamscan` and CMake cache hash to
`5751e89a0456f52c8a917877db55a690d7e46fdb6223544018b57b7f992726c2`,
`812a8b396786f5051d6523136e3e6b53d7cb8e520ce0739bf0ff9dc7e13d3949`,
and `127534b6724c2b70285e823b9613dc4a4f8318966d9d0f10f17a54ed9b810f1f`.

An initial non-edge CTest attempt, job
`job_9d8453f864ca4a248969710d474d88a0`, passed 31/32 but failed
`libclamav_rust` before its assertions: Cargo tried to create its default
Git-dependency directory under read-only `/src/build` because the run
omitted the offline Cargo home. This result was not treated as a pass.
The corrected full rerun used `CARGO_NET_OFFLINE=true`,
`CARGO_HOME=/build/cargo`, `RUSTUP_TOOLCHAIN=stable`,
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`,
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`, and an LV-backed
`TMPDIR`. Managed job `job_0760b2fa62c64a62a153c3184dded111` exited
0: **32/32 non-edge CTests passed** in 219.40 seconds, including
`libclamav_rust` and `libclamav`.

## Exact-edge raw API case

The registered `largefile_library_exact_32g` case used the same
34,359,738,368-byte, fully materialized, read-only
`/ram/edge-stable.bin` as the v7 Release case. Its name is misleading:
the bind is backed by root ext4, not tmpfs. Before and after the run,
the fixture retained 67,108,880 allocated 512-byte blocks, inode
8149459 and mtime 1790047133. The exact EOF-minus-16 marker and earlier
full-file SHA-256 oracle are documented in the v6 and v7 Release R05
receipts. This test reads the existing fixture; it does not create a
32-GiB disk spool.

Managed job `job_7bc5eccba9cb448789422d85532fa99f` wrapped CTest's
exact-edge case with the v7 process-tree sampler, a case-private disk
temporary directory, leak-detecting ASan and halt-on-error UBSan options,
and a 1,800-second Check case allowance. It exited 0. CTest reported
`Checks: 1, Failures: 0, Errors: 0`, `1/1` passed, in 1,026.90 seconds.
The single Check case calls `cl_scanfile_ex2`, `cl_scandesc_ex2`, and
`cl_scanmap_ex2` and asserts the expected detection, report, exact alert
offset, root size and policy ceilings for each API; the console summary
does not list the three calls separately.

The resource row contains 8,045 ordered samples, 315,088/308,037 KiB
peak RSS/PSS, an 8,192-byte sampled temporary peak, and zero sampled
swap, OOM and OOM kills. The case-private temporary directory was empty
afterward. The copied source manifest, test binary and CMake cache
hashes match their resource-row identity fields. Post-run qualification
LV free space was 28,033,110,016 bytes; root free space was about
100.7 MiB. The exact-32-GiB OneNote disk spool therefore remains unsafe
without additional LV headroom.

| Retained artifact | SHA-256 |
| --- | --- |
| `provenance/test.log` | `038c65bf8ec40c3abbb4957394fb2b6b5f0fb6832a947ed5d3d3bdeb478438d6` |
| `provenance/acceptance-case-resources.tsv` | `39eb18e61bf5c4a93d882be80db381b78db9c51f483c048625aec527d2f68ed6` |
| `provenance/samples.tsv` | `3a700e732f04894aa42892e3fd0dbdea8d394fb0cc3bb1eef04c2a97435c4ea5` |

Evidence root: `/qualification/r05-v7-library-exact32g-20260929-asan`.
Post-run full-file fixture hash job `job_3d8f075e87634516b5c3377ac1b56019`
exited 0 and returned
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`,
matching the v7 Release post-run hash and the earlier v6 full-file oracle.

This is C-linked ASan/UBSan evidence, **not** Rust-source sanitizer
instrumentation. It does not replace v7 full-size OneNote clean/positive
parity, service/production-CVD, all ingress, on-access, PCRE, or final
release-readiness evidence. No capability was promoted. No software,
usage reset, GitHub push, or GitHub workflow was used.
