# R12 Sonic1 v6 fully materialized OneNote clean parity — 2026-09-29

## Scope and frozen candidate

This receipt qualifies **one exact-32-GiB custom-signature CLI clean parser
case** on the current v6 source. It is not the full OneNote family, R12
matrix, production-CVD/service canary, Rust source sanitizer, or release gate.
The host/profile are `sonic1` / `sonic1-camera-key`; the pinned container is
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
Both scans ran as UID/GID 1000 with `/qualification` on the dedicated
disk-backed LV and a private case spool.

The deterministic v6 source archive is 17,907,786 bytes, SHA-256
`6a886cf5269cda75c2e8f300cb0dd3772592b2a19ffd29c7cf5a31d272652987`.
MCP-SSH transfer `transfer_26b9fdda6e42413aa3261159939562fa` used a
fresh one-time handoff and atomic commit. Independent Sonic1 `sha256sum`
matched; extracted bytes regenerated and bytewise matched the embedded
Git-less source manifest SHA-256
`c19b0777b9580611ec879bdbfb2740621aaf8bdbcc9f0a1f1189415be9c8fe5b`.
No previous transfer record was used as provenance. Local source guards
passed, including the 604-capability manifest; `git diff --check` passed.

The v6 source differs from v5 only in the clamscan ignore-signature test.
The v5 broad CTest exposed its stale assumption that all 53 corpus inputs
must be parse errors when the test alert is ignored. The v5 scanner actually
returned 34 complete-clean and 19 error results after the PE overlay fix;
the known malformed controls still failed closed. The repaired v6 test
checks one result per input, no `FOUND`, required malformed controls, clean
PE/OneNote controls, and summary counts reconciled to the per-file outcomes.
Its focused registered `clamscan` job
`job_b248cc4c04794503abee36d043488b0d` passed 1/1.

| Build | Configure job | Completed build job | Full non-edge CTest job | Result |
| --- | --- | --- | --- | --- |
| Release | `job_621871f64f064cbeace55d96fdf6d6ec` | `job_3c70c40cd8434e9c8927e909070a25d8` | `job_ba680ad090354be3b5acab9dcbb75177` | 32/32 in 254.53 s |
| C ASan/UBSan | `job_689d6a2d0d944a319a68d86de6fa1234` | `job_3f8cd60923054a1c97d7439abc3a960b` | `job_6f259ff5a2e44b898988ec7f987144ed` | 32/32 in 418.98 s |

Both builds used the installed stable Rust toolchain, existing Cargo cache,
and `CARGO_NET_OFFLINE=true`. The C sanitizer build used address/undefined
sanitizers and frame pointers; all 543 recorded C/C++ compile commands
contained both required flags. Its tests used
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. The first sanitizer
build job `job_d923bc2081c64f6694dd0ec57bb72d88` ended at its default
300-second MCP-SSH limit with `remote_may_still_be_running=false`, not a
compiler error. The incremental managed continuation above, explicitly
approved for 600 seconds, completed the same build with exit 0. These are
**C/C++ sanitizer** results; stable Rust is not compiled with Rust nightly
`-Zsanitizer=address`.

| Identity | Release SHA-256 | C ASan/UBSan SHA-256 |
| --- | --- | --- |
| `clamscan` | `353e424176464b972d07cbe2bb7e2cf7cdb3f015140a285144c93772819d5555` | `c95d2b99f01427b4bc2e76910bf775dc3abc9d1bda5f6490021685eabb0466e7` |
| `CMakeCache.txt` | `c9e1473effc653f8e63ca8631e5b8954256281fd9fc84ee4599f383e7a2c5f00` | `036acc0b132d131dd8095372b82209d539815c2e44c0c454157aae1e218fba66` |

## Exact clean controls and results

The clean NDB SHA-256 was independently verified in both case roots as
`4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`.
The prior independent bounded oracle read all 34,359,738,368 fixture bytes,
found zero occurrences of its literal, and verified fully allocated storage
with first hole at EOF; oracle-result SHA-256 is
`f36d13d05f436c6b1ee2b1e31daea156c7fb93c8deb5bce9bd4335c30c4e801e`.
Before and after both v6 runs, the fixture retained 67,108,864 allocated
512-byte blocks, inode 1619, and mtime 1790541183. Both scanner logs
independently computed its SHA-256 as
`1c593530684ac8c98d818437db669e556966051e4b1c4b4e9a65c049623feacf`.

The Release case root is
`/qualification/r12-v6-onenote32g-clean-20260929-release`; the C sanitizer
case root is `/qualification/r12-v6-onenote32g-clean-20260929-asan`.
Both used `--force-to-disk=yes`, explicit 32-GiB file/contiguous/PCRE
limits, 64-GiB scan/temporary limits, the isolated NDB, an empty cert
directory, `--alert-exceeds-max=yes`, and the case-private spool. The
sanitizer's original 52,297-byte OneNote also returned structured
`COMPLETE`, status 0, two scanned files, and no sanitizer stderr before
the full-size run.

| Observation | Release | C ASan/UBSan |
| --- | ---: | ---: |
| Managed full-scan job | `job_74bcb75f5a41487e9b4535636a761e18` | `job_0a01243b599d4452b09907fac0f663b8` |
| Command exit / report status | 0 / 0 | 0 / 0 |
| Completion and root type | `COMPLETE`, `CL_TYPE_ONENOTE` | same |
| Root bytes / logical bytes | 34,359,738,368 / 34,359,738,912 | same |
| Matcher bytes / temporary bytes | 34,368,129,568 / 34,359,720,552 | same |
| Files / parser ops / detector ops / skipped ops | 2 / 2 / 2 / 0 | same |
| Report elapsed | 199,388 ms | 316,222 ms |
| Process-tree samples | 200 | 317 |
| Peak RSS / PSS | 99,752 / 96,901 KiB | 138,960 / 136,174 KiB |
| Peak apparent temporary tree | 68,495,998,976 bytes | 68,575,809,536 bytes |
| Peak swap / OOM / OOM kills | 0 / 0 / 0 | 0 / 0 / 0 |

An independent read-only check found the two JSON reports identical after
excluding only `elapsed_ms`. It also checked each resource row's source,
binary and config hashes against the retained copied files; each ordered
sample sequence and RSS maximum; zero sampled swap/OOM; and temporary peaks
below 64 GiB (68,719,476,736 bytes). Apparent temporary-tree size is
not physical LV allocation. Each case-private spool was empty afterward.
Subsequent source review found that this v6 sampler summed a OneNote spool
and its hard-link owner pathname twice. These historical peaks are
conservative path-sums, not unique-inode usage; see
`R13-hardlink-temporary-sampler-correction-2026-09-29.md`. The original
artifact hashes and observed under-64-GiB upper bounds remain unchanged.
Container `memory.events` ended with `oom=0`, `oom_kill=0`; Sonic1 host swap
was disabled. The dedicated LV returned to 34,628,620 KiB available after
the sanitizer case. The v6 scanner logs each contain only the matching
input hash and `OK` line, with no sanitizer stderr.

| Retained artifact | Release SHA-256 | C ASan/UBSan SHA-256 |
| --- | --- | --- |
| `scan-report.jsonl` | `5068620596862c83e100bc90365bd19750b34fb0c592447e16cd19d796a30672` | `be3d8e24c94de85302aafdf13c5d65d01331c3f89d21407dda28227e197b8992` |
| `provenance/acceptance-case-resources.tsv` | `5a7b1a677ea7956842df7d3da30824bf44bbb6d8cd6bb27e15d874ea82faf6f0` | `8e99b64162b356603cdc57219fbb64e7e8346939ded1f933c5442d33798f44c4` |
| `provenance/samples.tsv` | `bdcf5711930455a8dd8da511b732b8aad95236e8f88b7b0b9839f51cb0593e77` | `8c1b7fbf818b507153b44a9dd5d4e9b50c72dbb64fca5e07392fa213bcd1915e` |
| `provenance/scan.log` | `ff4656eb02b436b19bd852baaa7bf72a2cb07cb12216c00aa59f4950d4c12b66` | same |

## Storage incident, cleanup and remaining gates

Sonic1's `/tmp/clamav-disk-ext4-v2` is a loop-mounted sparse image backed
by the nearly full root filesystem, not independent disk capacity. Moving
the generated v5 Release build there filled the host root and prevented a
new MCP-SSH async job directory from being created. The move was reversed,
and `fstrim -v` on that specific test filesystem discarded 32.2 GiB of
*free* blocks; the backing image's allocated blocks fell from 9,357,120
to 6,764,344 and root free space recovered to about 108 MiB. No active
file was deleted. Do not use that loop image for additional build archives.

To preserve disk-spool headroom without writing the loop image, completed
generated v4 Release, v5 Release and v4 C-sanitizer build trees were
temporarily parked in the pinned container's private `/dev/shm` as
`*-parked` directories. The original deterministic source archives and
case evidence remain on durable `/qualification`; the parked build trees
themselves are ephemeral and must not be assumed available after a
container restart. Private `/dev/shm` had 1,824,344 KiB free afterward.
No software was installed, no banked/usage reset was used, and no GitHub
push or `CMake Build` workflow was triggered.

This exact clean case closes the v4 PE-overlay false-incomplete regression
for Release and C sanitizer under the isolated control. It does **not**
promote `CL_TYPE_ONENOTE` or the overall capability matrix from pending:
malformed/fault and other input families, full ingress, production CVDs,
fanotify, service canary, Rust-source sanitizer, and final release
readiness remain open.
