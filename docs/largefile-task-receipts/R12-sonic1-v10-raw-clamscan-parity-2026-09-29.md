# R12 Sonic1 v10 exact-32-GiB raw ClamScan parity — 2026-09-29

## Scope and provenance

This is direct-file raw ClamScan evidence for the frozen v10 source package,
not full ingress, deep parser, PCRE, production-CVD, or release qualification.
The source transfer, Git-less manifest and coherent builds are recorded in
`R03-sonic1-v10-source-bound-builds-2026-09-29.md`. Source manifest SHA-256:
`a8bcd93903525147ababd91633e6764e570136ff4239332cb73c60d3e62a3d6a`.
All cases used Sonic1 profile `sonic1-camera-key` and container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
Only one full-size workload ran at a time.

The read-only `/ram/edge-stable.bin` bind is ext4-backed, not tmpfs. It is a
fully allocated regular file of exactly 34,359,738,368 bytes, with
34,359,746,560 allocated bytes, inode 8149459 and mtime_ns
1790047133231907996. `SEEK_HOLE` returned EOF and the last 16 bytes are
`EDGE-LATE-MARKER`. A full-file SHA-256 pass before this series, managed job
`job_35fd8c1e33744863bc9c7cb84714ff73`, and another after all four
scans, job `job_1d3a0f425db34351906658c7cf481004`, both exited 0 and
returned `98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
The final size, allocation, inode, mtime, hole-at-EOF and end marker were
rechecked unchanged. Each ClamScan log independently records this input hash.

The clean-control NDB SHA-256 is
`4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`;
the late-marker NDB SHA-256 is
`24f6061b35491ee66a054b4a67145d138356188aeb2e16cd3bdcf98925fd1300`.
Both were copied and verified in case-private evidence roots. The v10
Release/C-sanitizer `clamscan` hashes are
`a3ae4989218dc5a917fc768b7ef983cc20b63d9bc907b1d7a9652377370b07ca`
and `87c34994e207cdf3c20f03012f796d0717db505a2def4f08b7a3ddf647a7a13d`;
their CMake cache hashes are
`0fc3d24b3f10929cbff0cb299d155decbf815f4e4ff5b8b7efedf21ac2e4beb1`
and `0697e08a37ed49d5003b701ebefc1e5521b81980a8d6b73f7ebb74b1ab303d64`.
The resource rows bind the copied source, scanner and cache hashes.

## Four separate exact-size cases

All cases used explicit 32-GiB file / 64-GiB scan and temporary limits,
case-private disk-backed temporary directories, JSON reporting, full-file
hash logging and process-tree resource capture. Positive cases also set
`--max-contiguous-size=32G`. C sanitizer cases used
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.

| Mode and expected case | Managed job / exit | Report status, verdict, completion | Samples | RSS/PSS peak KiB | Temporary/swap/OOM |
| --- | --- | --- | ---: | ---: | --- |
| Release clean | `job_539a6bd8bba0480fa8c7ac2f67a618b5` / 0 | 0, 0, `COMPLETE` | 1,838 | 100,792 / 98,041 | 0 / 0 / 0 |
| Release late-marker | `job_e0f3163fc86643c4817d26080662c5da` / 1, expected detection | 1, 2, `DETECTION_TERMINATED` | 1,835 | 100,408 / 97,583 | 0 / 0 / 0 |
| C ASan/UBSan clean | `job_ed9eba2242814272a1bb2fc1d0732cd8` / 0 | 0, 0, `COMPLETE` | 2,684 | 139,764 / 136,936 | 0 / 0 / 0 |
| C ASan/UBSan late-marker | `job_0ac6f9771b4c4a01b180351af7b6b43c` / 1, expected detection | 1, 2, `DETECTION_TERMINATED` | 2,682 | 140,068 / 137,245 | 0 / 0 / 0 |

Each report identifies `CL_TYPE_BINARY_DATA`, exact 34,359,738,368-byte
root/logical size, 34,368,129,024 matcher bytes, one scanned file, no skipped
operation, and zero temporary bytes. Clean reports have no alert; positive
reports name `NDB.LargeFile-Edge.UNOFFICIAL` at offset 34,359,738,352.
The logs record the matching input hash, `OK` or the exact signature `FOUND`;
the sanitizer logs have no ASan/LSan/UBSan diagnostic. All case-private
temporary directories were empty afterward.

For each case, a separate read-only verifier exited 0 after checking the
copied source/scanner/cache and DB hashes, exact report fields and outcome,
the independent input hash in the log, every consecutive sample sequence and
strict timestamp, stable root PID and unique PID sets, resource row versus
trace RSS peak, zero swap/OOM, sanitizer diagnostics where applicable, and
temporary cleanup. Retained artifact SHA-256 values:

| Case | JSON report | Scan log | Resource row | Ordered samples |
| --- | --- | --- | --- | --- |
| Release clean | `8e32e08e2a8a3ae934a78b9ffb2abbc2d63e39bf96c939d68cb48b13207da2a4` | `d5a059ee4d11e33377bad2adedd7931ee98c0d382d8f4f5a376fae1f8b09de6f` | `d70f81f2dadd5eef8401c392d79cb777061a4159a93b1e1d9cf6877decabc6b0` | `438d35d69538787d244b812525226177f689edaa6d5756ab1a50ed9f05522807` |
| Release late-marker | `1742a93f2e96fbc34669c71f287a8a6ca1d994faf1ed4396368b832efa4db903` | `bcd5ecfbd57d0fe12d6ca48e680ee25d5e1b359f90c76d332907f33da530746d` | `6a81ffc4b617f57e71a4cb997ef494f9670efad5c607b5e9e34070bea3fe1d18` | `af332422c0592c155be029c95d6db55ed8f662262c2fb9133576d1d7f2a360cc` |
| C sanitizer clean | `6dc7fa36a39703fe364c586a971f3cfe973827ab44af915cbc0bb2ef139d8f90` | `1b4de20f68877b362c510588baa319398d8eb4bd644a27910b848a2daaa70943` | `72d7fdc89f288af3adfb9ddb527469f86e8874ffab91b53db427fb36be4c06ef` | `7a4c1c378515800922f4e8393410343f70476083fb20cfc58ee13f24afb900cc` |
| C sanitizer late-marker | `c65cecf6830cfc5478643c5b08f8362e834b4b42448f9b6ce02f0cfb0791e5fd` | `71030d344005b82f45148b5a97d128b279496d4d5fdfc9af6efc733ae2a5a16d` | `19d229b9c307a9d677892d7a225077d065645dc27a1902d1288642d843d5de1f` | `84f15ae8b39036b77a7bd0822015fdf60e36dccc89b879de7e7a820304590707` |

Case roots are `/qualification/r12-v10-raw-clamscan-{clean,edge}-20260929-{release,asan}`
with the appropriate choice of each brace term. This is current-v10 exact
raw-file clean/detection parity only. It does not prove stdin, daemon/client,
on-access, disk-spooled deep parsing, full PCRE, production-CVD or Rust
sanitizer coverage. A post-case read-only diagnostic found about 23.65 million
KiB `MemAvailable`, no swap, and 7.39 billion bytes free on `/qualification`,
below the contractual 48-GiB memory and 68-GiB disk admission for those
larger cases. No capability status was promoted.

State: `v10-raw-exact-release-and-c-sanitizer-clean-detection-passed; final-fixture-sha-verified; release-gates-open`
