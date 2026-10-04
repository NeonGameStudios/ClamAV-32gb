# R05 Sonic1 v10 exact-32-GiB library API parity — 2026-09-29

## Scope and source identity

This records the three modern library entry points in the registered
`largefile_library_exact_32g` CTest, not full ingress, parser, production-CVD,
or release qualification. The v10 deterministic source package and build
provenance are recorded in `R03-sonic1-v10-source-bound-builds-2026-09-29.md`.
The source manifest SHA-256 is
`a8bcd93903525147ababd91633e6764e570136ff4239332cb73c60d3e62a3d6a`.
Both cases ran in the pinned Sonic1 container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
from image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`,
using `sonic1-camera-key`. `/qualification` is disk-backed; the `/ram` fixture
mount is read-only, ext4-backed, and is **not** tmpfs.

The fixture `/ram/edge-stable.bin` is a regular, fully materialized file of
exactly 34,359,738,368 bytes with 34,359,746,560 bytes allocated. It has
inode 8149459, mtime_ns 1790047133231907996, `SEEK_HOLE` at EOF, and
`EDGE-LATE-MARKER` at EOF minus 16. Its pre-run SHA-256 was
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
The separate full-file post-Release hash job
`job_a09e2c0844c14d2f91b30773fb4622a6` and post-sanitizer hash job
`job_35fd8c1e33744863bc9c7cb84714ff73` both exited 0 with the same
SHA-256. The post-sanitizer size, allocation, inode, mtime, hole-at-EOF and
end marker were rechecked unchanged.

## Release exact-size case

Evidence root: `/qualification/r05-v10-library-exact32g-20260929-release`.
Its copied source manifest, `check_clamav`, and CMake cache match SHA-256
`a8bcd93903525147ababd91633e6764e570136ff4239332cb73c60d3e62a3d6a`,
`29119715ded894878338b71c95f152a49066be4541df0e760df50dac2e487c13`,
and `0fc3d24b3f10929cbff0cb299d155decbf815f4e4ff5b8b7efedf21ac2e4beb1`.
Managed job `job_50aea038877f4ffa9ee291fd80dc6400` exited 0. CTest
reported 1/1 passed in 620.67 seconds. The source test checks
`cl_scanfile_ex2`, `cl_scandesc_ex2`, and `cl_scanmap_ex2` against the exact
end marker and expected offsets/verdicts.

The wrapper retained 5,750 ordered process-tree samples, with 118,668 KiB
peak RSS, zero sampled temporary allocation, swap, OOM events and OOM kills.
The private temporary directory was empty. An independent read-only verifier
exited 0 after checking copied identities, all consecutive sample sequences,
strict timestamps, root PID and unique PID sets, row/trace RSS agreement,
CTest outcome, resource limits and cleanup.

| Release retained artifact | SHA-256 |
| --- | --- |
| `provenance/test.log` | `f99d57efd0a7483cc3b1aca3a4c4b4f396a96df87c957a68ae907fa13d389ba8` |
| `provenance/acceptance-case-resources.tsv` | `bcc4848fd690aef5693cf643fc6b8bdc1ab8a5a515c38707d0676c5eeda12b84` |
| `provenance/samples.tsv` | `5d12630eb4bcdd390f998e557c478acc131e44d1fe76552ac891acba32b0fe04` |

## C ASan/UBSan exact-size case

Evidence root: `/qualification/r05-v10-library-exact32g-20260929-asan`.
Its copied source manifest, `check_clamav`, and CMake cache match SHA-256
`a8bcd93903525147ababd91633e6764e570136ff4239332cb73c60d3e62a3d6a`,
`077589d09357a35505a5f3240b43fac32af6225d3065ee1f40abdcd3afc70edb`,
and `0697e08a37ed49d5003b701ebefc1e5521b81980a8d6b73f7ebb74b1ab303d64`.
Managed job `job_e4b83b3ed2194882a8d03f5e1e135124` used
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`; it exited 0. CTest
reported 1/1 passed in 1026.76 seconds. No sanitizer diagnostic appeared in
the retained log. The C sanitizer build does not instrument stable Rust.

The wrapper retained 7,937 ordered samples. Peak RSS/PSS were
296,936/289,689 KiB; sampled temporary allocation, swap, OOM events and
OOM kills were zero. The private temporary directory was empty afterward.
A separate read-only verifier exited 0 after checking source/binary/cache
hashes against the resource row, every sequence and timestamp, stable root
PID and unique PID sets, row/trace peak equality, log result, zero resource
violations, absence of sanitizer diagnostics, and cleanup.

| C sanitizer retained artifact | SHA-256 |
| --- | --- |
| `provenance/test.log` | `df778321a4cbcdfc8620946cb9fee2884686022de690bd4e2dddfbfe70bf48f0` |
| `provenance/acceptance-case-resources.tsv` | `58b931141c02077c17bc3b65f108a9eabd92dc95dda6fedddc91df0bd3b214c4` |
| `provenance/samples.tsv` | `f74a00db0b90e8f74d4ae2cd2aca2ebd812c99a5aceb956d463173650b812c8d` |

The exact-edge three-API Release/C-sanitizer slice passed on v10. Required
clean, limit and failure cases for those APIs, other ingress paths, full
materialized deep parsers, Rust sanitizers, full PCRE phases, production CVDs,
and final admission/readiness remain open. No capability status was promoted.

State: `v10-exact-three-api-release-and-c-asan-passed; post-run-fixture-sha-verified; release-gates-open`
