# R12 Sonic1 v9 exact-32-GiB raw ClamScan clean/detection — 2026-09-29

## Scope and provenance

This is direct-file raw ClamScan evidence for the frozen v9 source package,
not full ingress, parser, production-CVD or release qualification. Source
transfer, extracted manifest and coherent build details are in
`R03-sonic1-v9-source-bound-builds-2026-09-29.md`. The Git-less source
manifest SHA-256 is
`884ba2f7a7e180a063c48bb62a8417e20277dee9c849c2f8e307bfdc50fb06b0`.
The pinned Sonic1 container is
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
Profile: `sonic1-camera-key`.

The shared `/ram/edge-stable.bin` mount is read-only and ext4-backed, not
tmpfs. The fully allocated regular fixture is exactly 34,359,738,368 bytes;
its 67,108,880 allocated 512-byte blocks, inode 8149459 and mtime
1790047133 were checked before the cases. `SEEK_HOLE` returned EOF, and an
independent 16-byte read at EOF minus 16 returned `EDGE-LATE-MARKER`. The
independently rechecked full-file SHA-256 oracle is
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
The clean-control NDB SHA-256 is
`4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`;
the late-marker NDB SHA-256 is
`24f6061b35491ee66a054b4a67145d138356188aeb2e16cd3bdcf98925fd1300`.
Both were copied to separate case-private evidence roots.

## Release clean and late-marker results

The v9 Release `clamscan` and CMake cache SHA-256 values copied into each
case root are
`83dee8840b488f79d95b636e6f914bb831b16d55c233bba6d2f943a4c9ffded9`
and `6e80757e0e72b8fba04529ea43d9324670bb4e0848dd368c1edc175fe25addf5`.
Both scans used explicit 32-GiB file / 64-GiB scan and temporary limits,
case-private disk-backed temporary directories, JSON reporting, full-file
hash logging, and the v9 fail-closed process-tree resource wrapper. Neither
forced disk spooling. Case roots:

- Clean: `/qualification/r12-v9-raw-clamscan-clean-20260929-release`
- Positive: `/qualification/r12-v9-raw-clamscan-edge-20260929-release`

| Measure | Clean, `job_53e129623eb84d6ea11816a4623997d1` | Positive, `job_fcc88311f67848d280b9627f17530f37` |
| --- | ---: | ---: |
| Managed exit | 0 | 1, expected detection |
| Report status / verdict / completion | 0 / 0 / `COMPLETE` | 1 / 2 / `DETECTION_TERMINATED` |
| File type / root and logical bytes | `CL_TYPE_BINARY_DATA` / 34,359,738,368 | same |
| Matcher / temporary bytes | 34,368,129,024 / 0 | same |
| Exact alert / offset | none | `NDB.LargeFile-Edge.UNOFFICIAL` / 34,359,738,352 |
| Files / skipped operations | 1 / 0 | same |
| Ordered samples | 1,812 | 1,839 |
| Peak RSS / PSS (KiB) | 100,760 / 97,964 | 100,496 / 97,696 |
| Sampled temporary / swap / OOM / OOM-kill | 0 / 0 / 0 / 0 | same |

The clean scanner log reports the independent SHA-256 and `/ram/edge-stable.bin:
OK`. The positive log reports the same file hash, the exact named signature
`FOUND`, and the raw matcher debug offset 34,359,738,352. Both case-private
temporary directories were empty afterward. A separate read-only verifier
exited 0 after checking both reports and expected outcomes, copied source /
binary / cache hashes against their rows, all consecutive trace sequences and
increasing timestamps, stable root PID inclusion and valid PID sets,
trace-versus-row RSS peaks, zero resource violations, exact logs and oracle,
and empty temporary directories.

| Retained artifact | Release clean SHA-256 | Release positive SHA-256 |
| --- | --- | --- |
| `scan-report.jsonl` | `2539119864703219c3c739aba56c7e0ce1b3f5223ebd8439e65a6fc481957f50` | `3e94f1988d95e9395c90f1f6ad6b628f51a993a3452ec3d7be4391bb84bdc9fd` |
| `provenance/scan.log` | `9b3ebe4eea34ee53f5aabf0b50fd5012bd6573d34e11a32128967fca773f4b30` | `ca1b613ec3c2dddd5afee618975ddd360ddfd6622615db276dfcc4317bf95206` |
| `provenance/acceptance-case-resources.tsv` | `2aa0a6f6998a26b27d787c5f64a73d0f5f53c8ca9ce672fb5fef764f6192a18a` | `04ff980a8b15f7c6a3bcf7558716389b2795d73a6edefb1aee683c23523cd015` |
| `provenance/samples.tsv` | `e1c17d8c2fdbce332e713b77d939d1562e9e8b8935bd3bd3b866e166d65cbdae` | `47146e8658569cc185587d0a971c1a8490479fa8cd428ae861697942d5a78132` |

## C ASan/UBSan clean result

The v9 C sanitizer scanner and CMake cache copied into the case root hash to
`7b56f0f166512073f39e23c8b1daf26b50733385b054a67cdb979c4505c270ef`
and `1d2be36a7087eed76c5a4c88ceb93997edda5a5c64c5f23330b0efe57c50e5b6`.
The same frozen source and clean-control DB were used. Managed job
`job_3a3eace3c3b04230847740c75272b0c8` exited 0 with
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. Its evidence root is
`/qualification/r12-v9-raw-clamscan-clean-20260929-asan`.

The report says status/verdict 0/0, `COMPLETE`, `CL_TYPE_BINARY_DATA`, exact
32-GiB root/logical bytes, 34,368,129,024 matcher bytes, one scanned file,
zero skips and zero temporary bytes. Its log records the expected full-file
SHA-256 and `OK`, without ASan/LSan/UBSan diagnostics. The resource wrapper
wrote a complete row from 2,694 samples: RSS/PSS peaks 139,716/136,834 KiB;
zero sampled temporary, swap, OOM or OOM kills. The spool was empty.
A separate read-only verifier exited 0 after checking copied source/binary/
cache hashes against the row, all ordered samples and PID sets, trace/row RSS
peak equality, exact clean report and input hash, zero resource violations,
absence of sanitizer diagnostics, and cleanup.

| C sanitizer clean artifact | SHA-256 |
| --- | --- |
| `scan-report.jsonl` | `3e1939a18cd7992f9487deb3d8dafc9f2beeaf6afd60c2bd2c595f680c06f39a` |
| `provenance/scan.log` | `18b8ee72547b929d18bc9075207aaf4dde8f939910ae86b0fcdddbd3eec987c1` |
| `provenance/acceptance-case-resources.tsv` | `abd2a4fb3460830dd3b8768ae045f5458ac72484bd57447db96384755cbb8ee9` |
| `provenance/samples.tsv` | `275c27f4e41423c5e279dec7ecf6ce73cb4b254036809c9bb74408b8fd2cdcaf` |

## C ASan/UBSan late-marker result and boundary

The separate C sanitizer positive root is
`/qualification/r12-v9-raw-clamscan-edge-20260929-asan`. Its copied scanner,
CMake cache and late-marker NDB hashes match the corresponding v9 identities
above and the Release positive DB. Managed job
`job_c16896ff196e4452ac5a4a4963c763ca` returned the **expected
detection exit 1** while the resource wrapper wrote a complete row. The
report says status/verdict 1/2, `DETECTION_TERMINATED`, exact 32-GiB
root/logical bytes, 34,368,129,024 matcher bytes, zero temporary bytes,
`CL_TYPE_BINARY_DATA`, and `NDB.LargeFile-Edge.UNOFFICIAL` at
34,359,738,352. The log independently names the exact match offset and
full-file SHA-256. There was no ASan, LSan or UBSan diagnostic.

The resource row records 2,701 ordered samples, RSS/PSS peaks
140,144/137,272 KiB, and zero sampled temporary, swap, OOM or OOM kills.
The case-private spool was empty. A separate read-only verifier exited 0
after checking the copied source/scanner/cache hashes against the row,
consecutive sequences and increasing timestamps, stable root PID and valid
PID sets, trace-versus-row RSS peak equality, exact report/alert/offset/log
and file hash, zero resource violations, no sanitizer diagnostic and cleanup.

| C sanitizer positive artifact | SHA-256 |
| --- | --- |
| `scan-report.jsonl` | `810ad1dc0d90188f67a50d534725cf1d999ab24f9342ab0b9e58cad7a75ad88a` |
| `provenance/scan.log` | `fdaee78a6c497a399822e27f9a75733e1e7708c44908a361c9058eacc4288385` |
| `provenance/acceptance-case-resources.tsv` | `b73c84f1cf6fe52c29d8715e803d0f6e0a878f8d00dbad5d665db2064e08e07f` |
| `provenance/samples.tsv` | `ffe69dcc0567ee517db9e8273df604a6b7604faf2d56d6c5ad06cff3999dd0e7` |

This is current-v9 exact raw file clean/detection parity for Release and
C-sanitizer builds only. It does not prove stdin, daemon/client, on-access,
disk-spooled deep parsing, full PCRE, production-CVD or Rust sanitizer
coverage. The fixture was independently rehashed after all four runs under
managed job `job_87c25c531f61400399a9e733f8f92abe` (exit 0); its SHA-256
still equals
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
No capability status was promoted.

State: `v9-raw-exact-release-and-c-sanitizer-clean-detection-passed; final-fixture-sha-verified; release-gates-open`
