# R12 Sonic1 v8 exact-32-GiB raw positive ClamScan parity — 2026-09-29

The frozen v8 source, transfer, container and build provenance are in
`R12-sonic1-v8-raw-clamscan-clean-2026-09-29.md`. Source manifest SHA-256
is `f71a59692fd63357ba6f1ff362275cfadddfd20f6f01ac8b3edc5cb9ec99e723`.
The v8 Release and C ASan/UBSan builds each passed 32/32 non-edge CTests
before these scans. Case-local scanners hash to
`6709ea869b8f800d63bce27c024350d41abc6b78fc3ebdef0a73fb75c2e0da04`
and `0eade76a1ccb1761994568934361661f26facd163d01a1ee84dac1e69dda5876`;
their CMake caches hash to
`1ca43701cd73d194a326466578027445edb4dda5c0fe48332672d41ce8f4bde3`
and `df647e505b1ec18717e4d251bc1f5cb3500353536fd910a764aa87281fbbe07d`.
The isolated `large-edge.ndb` SHA-256 in each case is
`24f6061b35491ee66a054b4a67145d138356188aeb2e16cd3bdcf98925fd1300`.

The read-only, fully materialized fixture `/ram/edge-stable.bin` is backed
by root ext4, not tmpfs. Its size, allocated blocks, inode and mtime were
unchanged after the pair: 34,359,738,368 bytes, 67,108,880 512-byte
blocks, inode 8149459, mtime 1790047133. The exact marker is at byte
34,359,738,352, and both scanner logs independently reported input
SHA-256 `98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.

Managed Release job `job_34af21bcd26e4a7783897fa48b52ba7c` and
C ASan/UBSan job `job_1fbaff1c537e4000bfd60a7c102ae5ce` used
separate case-private LV-backed temporary directories, the same explicit
32/64-GiB limits, JSON reports, hash logging, empty certificate
directories, and the corrected v8 fail-closed resource wrapper. Neither
forced disk spooling. Both returned process exit 1 for the **expected
detection**, and both wrappers wrote complete resource rows. The C
sanitizer used `detect_leaks=1:halt_on_error=1` and UBSan halt/stacktrace
options; no sanitizer diagnostic appeared in its log.

| Observation | Release | C ASan/UBSan |
| --- | ---: | ---: |
| Report status/verdict/completion | 1 / 2 / `DETECTION_TERMINATED` | same |
| File type and root/logical bytes | `CL_TYPE_BINARY_DATA`; 34,359,738,368 | same |
| Matcher/temporary bytes | 34,368,129,024 / 0 | same |
| Exact alert/offset | `NDB.LargeFile-Edge.UNOFFICIAL` / 34,359,738,352 | same |
| Report elapsed | 192,190 ms | 338,888 ms |
| Ordered process-tree samples | 1,844 | 2,682 |
| Peak RSS/PSS | 100,932 / 98,048 KiB | 140,416 / 137,462 KiB |
| Sampled temp/swap/OOM/OOM-kill | 0 / 0 / 0 / 0 | same |

An independent read-only verifier checked both reports, exact alert and
offset, case-local source/binary/cache hashes against resource rows,
every consecutive sample number and increasing timestamp, stable root
PID inclusion, trace/row RSS peak equality, the exact scanner log match
and input hash, absence of sanitizer diagnostics, and empty post-run
spools; it exited 0.

| Retained artifact | Release SHA-256 | C ASan/UBSan SHA-256 |
| --- | --- | --- |
| `scan-report.jsonl` | `b4a014ff992240b419750febbd7f84249eb4053cb2e2e268805e97c36570f29f` | `d372579e5598a54b3c30c98d5ca7e5b998c68dc03d1a5b1aedf94995a7aa17c4` |
| `provenance/scan.log` | `9bcf9aa1b626724a8c006593f0d9563d14ca81a602ec1e174a70d53d3de5220d` | `2c5c0864e0eec16dbfa8fbe7bf2a45cfa8e8925ab30916afb60d764c610e5d1a` |
| `provenance/acceptance-case-resources.tsv` | `1358ce587ec501e2fd14a3b8a090be2e34a6dae512a5e608b757658fbf62ee1c` | `64a88c206475ee0c575b3445d8a2193cc343fd3b05bb4a41779d1110104ee413` |
| `provenance/samples.tsv` | `0ba75dae96556bf40469158dee4155c9b8b9a9f73e3b4b21487c608a8e8102af` | `434af20f5ca1ea4e60f456c643f44c75d322a74b8d72a6cba140af333bd942d6` |

Evidence roots are
`/qualification/r12-v8-raw-clamscan-edge-20260929-release` and
`/qualification/r12-v8-raw-clamscan-edge-20260929-asan`.
This proves direct-file exact-tail detection for these two builds, not
stdin, service, on-access, OneNote disk spooling, production-CVD canary,
or final release readiness. No capability was promoted.
