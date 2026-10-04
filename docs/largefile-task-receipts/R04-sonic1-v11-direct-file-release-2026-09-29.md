# R04 Sonic1 v11 direct-file Release cases — 2026-09-29

This receipt records two **case-private** `clamscan:file` acceptance records,
not a qualified capability or release. The required materialized
32-GiB-plus-one-byte limit case, sanitizer parity, other ingress modes and
the remaining capability matrix are still open.

## Source and coherent build

The dirty canonical checkout was frozen with
`tools/largefile_deterministic_source_package.py` into
`/private/tmp/clamav-r04-direct-v11-20260929.tar.gz` (17,919,287 bytes,
SHA-256 `5ef61338e20ac3e6bfc30061e672647d2cc4044308c0363b95d5f4d10f29d9a7`).
Its source-content manifest SHA-256 is
`bccafc652981c00f8f7b8f8b4091ff3c99c1420a1304f42d0abfa105eadf97d0`.
MCP-SSH durable transfer `transfer_4c91939389ff446f9d7b2cb418c6e816`
reached `ready_to_commit` with that expected checksum and committed by atomic
rename. The package was extracted at
`/qualification/source-r04-direct-v11-20260929` inside the pinned Sonic1
container `c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
(image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`).
The independently regenerated Git-less manifest compared byte-identical to
the packaged manifest. Source guards on the extracted tree passed in managed
job `job_9ee1fde1bd2b49f8b98c744496ff1b5b`, including the new direct
capture/producer tests and the 604-capability case map.

The first Release configure attempt (`job_4035d351879848118ad88e65931c6564`)
failed because the sanitized Docker environment did not set the already
installed Rust toolchain for an unwrapped `rustc -vV` CMake probe. A direct
probe verified Rust 1.97.1, host `x86_64-unknown-linux-gnu`; a subsequent
argument-order mistake (`job_a9cfafb7828742e9958cdcec9b260b27`) failed
before running CMake. The corrected configure (`job_434d341761604b48a422ca318949a3d9`)
and offline, two-job Release build (`job_c23f1f6dbbda418e9110b27782f1c587`)
both exited 0. The build tree is
`/qualification/build-r04-direct-v11-20260929-release`. Its CMake cache
points to the extracted source, enables large-file defaults and exact-edge
test, app, UnRAR, milter, clamonacc, shared/static libraries and WERROR,
with interpreter bytecode. Release non-edge CTest
`job_9004fd5485e3473da8c8a940851d48c7` passed 32/32 in 124.24 s;
the exact-32-GiB library test was intentionally excluded for separate
materialized testing.

| Artifact | SHA-256 |
| --- | --- |
| Release `clamscan` | `fbc5263f7655d587f69297f6ee5143c70639cd70c724969633dbceaf6e4dfcc8` |
| Release `clamd` | `19c1ac4d310a0a0661a3dc11f19c55bb1cba6cf6be02c21d8ee9c3dfca9e2e4a` |
| Release `clamdscan` | `65909bb7e8508d1d29fafbc1d9eedb96f7ab31db230876b14a45dc121bf2c26b` |
| Release `CMakeCache.txt` | `87093d862f8a8703a839c0168e10eaa94d5bbbad9f7fbe1f6e0b6a1657fa54f3` |

## Exact-size R04 cases

Both cases used the read-only, fully allocated `/ram/edge-stable.bin`, exactly
34,359,738,368 bytes, independently expected SHA-256
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
The input capture rehashed the file before and after each scan, compared
size/allocation/first-hole and stable identity, and retained identical
before/after sidecars. Each case had a pre-scan independent oracle binding
its expected outcome, source, binary, config and NDB hashes. The scan used a
case-private disk-backed temp directory, full-file hash logging, structured
JSON, explicit 32-GiB file/contiguous and 64-GiB scan/temp ceilings, and
procfs process-tree resources. The producer rehashed the actual input again,
then bound and verified the R04 row and resource sidecar. Neither case copied
the 32-GiB fixture into its evidence root.

| Case | Root / scan job / producer job | Outcome | Resource sample / RSS peak KiB | Case-row / report SHA-256 |
| --- | --- | --- | --- | --- |
| Clean | `/qualification/r04-direct-v11-release-clean-20260929` / `job_18eeefc0ec3247a7ae52e2e2a1b984fe` (0) / `job_6230df3ffbaa4980accff1a86bde72ce` (0) | `COMPLETE`, clean, logical 34,359,738,368, matcher 34,368,129,024 bytes | 1,831 / 101,076 | `ca149d4b4dbe5550118ba62bb442b2bde66532169411cc0d5622d5158cf886bb` / `ab440e1ada95193ae2a967a5b8f258d3bca57691dd64d72ea01f91db15103d94` |
| Detection | `/qualification/r04-direct-v11-release-detection-20260929` / `job_18b4b9cbb32a49b49283c908d8289485` (1, expected) / `job_2d5cddf8d83644b5ae842de6b7c61747` (0) | `DETECTION_TERMINATED`, `NDB.LargeFile-Edge.UNOFFICIAL` at 34,359,738,352 | 1,838 / 101,008 | `37297b0814128bef65d5d7743fbd3ec20d6fa721852fec1ea24cbd51b8ed9c03` / `34f41212697f41e71e2d455d35cd1256f503df293834a7ee05eda4c0160253f6` |

The clean and late-tail NDB SHA-256 values are respectively
`4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`
and `24f6061b35491ee66a054b4a67145d138356188aeb2e16cd3bdcf98925fd1300`.
Both resource rows report zero swap, OOM events/kills and temporary peak;
both case-private temp directories were independently observed empty. Their
resource-row SHA-256 values are respectively
`ff2ab0c789c7032358dcfa73867f82e2a7ae45808b50eeb1d00a3c5a33b37089`
and `6c1bdcbd27643bc3661edba9edc5ceb9c50ad8401f2c41cccd7036ac48710f34`.

## Remaining boundary

The current `/qualification` filesystem had 5,555,486,720 bytes free after
these cases; `MemAvailable` was 24,213,000,192 bytes with zero swap. The
required admission envelope is at least 68 GiB free disk-backed space and
48 GiB effective available memory. A prior 32-GiB-plus-one artifact at
`/qualification/r13-32gplus1-db0a-20260924` is compressed (`limit.bin.gz`),
not a materialized input; the read-only `/ram` fixture mount exposes 32-GiB
files but no 32-GiB-plus-one file. No sparse or compressed substitute was
accepted. C/Rust sanitizer parity, production-CVD/daemon/PCRE/fanotify and
all other R04 rows remain pending. The authoritative global
`docs/largefile-acceptance-cases.tsv` remains empty; these valid rows are
case-private and do not by themselves satisfy the full coverage gate.

State: `v11-release-direct-clean-and-exact-tail-r04-rows-validated; limit-and-release-gates-open`
