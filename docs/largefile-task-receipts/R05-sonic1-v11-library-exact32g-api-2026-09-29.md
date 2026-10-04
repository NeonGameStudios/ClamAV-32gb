# R05 Sonic1 v11 exact-32-GiB library API slice — 2026-09-29

This is current-source Release evidence for the `largefile_library_exact_32g`
CTest, **not** full library-ingress or release qualification. The test covers
late-tail detection through `cl_scanfile_ex2`, `cl_scandesc_ex2`, and
`cl_scanmap_ex2`. Required clean, fully materialized 32-GiB-plus-one-byte
limit, failure, sanitizer, and other ingress cases remain open.

The v11 deterministic source package, transfer, container, and coherent build
are documented in `R04-sonic1-v11-direct-file-release-2026-09-29.md`. The
source-content manifest SHA-256 is
`bccafc652981c00f8f7b8f8b4091ff3c99c1420a1304f42d0abfa105eadf97d0`.
The pinned Sonic1 container is
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
(image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`).
The case-private evidence root is
`/qualification/r05-v11-library-exact32g-20260929-release`.

Managed job `job_e45414d1652143c0b1cb605e899e042c` exited 0. Its retained
CTest log reports 1/1 passed in 622.48 seconds. The test source asserts the
exact expected `LargeFile.Library.32G.UNOFFICIAL` detection at EOF minus 16,
strong-indicator verdict, `DETECTION_TERMINATED` completion, exact report
offset, root size, scanned/matcher counters, and configured budgets for each
of the three APIs. This is one registered test process and one measured
resource row; it is not three independently produced R04 acceptance rows.

| Retained artifact | SHA-256 |
| --- | --- |
| `provenance/source-content.sha256` | `bccafc652981c00f8f7b8f8b4091ff3c99c1420a1304f42d0abfa105eadf97d0` |
| `provenance/check_clamav` | `1a569100946b8ead09681cd7392802692ebe79b6ad0a4cb28021846ad1632d2f` |
| `provenance/CMakeCache.txt` | `87093d862f8a8703a839c0168e10eaa94d5bbbad9f7fbe1f6e0b6a1657fa54f3` |
| `provenance/test.log` | `4cac0a8c243ac612fe1db0fd7d6d2765cbe6cbe3b3d0072f112504e78bcf5112` |
| `provenance/acceptance-case-resources.tsv` | `4ffca6591128402ee7111323494317fb347e0b18d3daf6d9bfb1f9d31bfea057` |
| `provenance/samples.tsv` | `8e8bdd85cb5e8f8310785e9f91e0c5a99f8a9542c3d977bcf8b967d30d06e447` |

An independent read-only verifier exited 0 after checking the resource row's
three copied hashes, Linux x86-64 sampler identity, all 5,766 consecutive
sequences and increasing timestamps, a stable root PID, unique sampled PID
sets containing that root, per-sample RSS relationships and row/trace peak
equality. Peak process-tree RSS/PSS were 119,820/112,629 KiB. Measured swap,
OOM events/kills and sampled temporary usage were zero. The private `tmp`
directory was empty after the job.

The read-only `/ram/edge-stable.bin` input is fully materialized, exactly
34,359,738,368 bytes with 34,359,746,560 allocated bytes, inode 8149459,
mtime_ns 1790047133231907996, `SEEK_HOLE` at EOF and the expected
`EDGE-LATE-MARKER` at EOF minus 16. The separate post-test full-content
checksum job `job_c19125cb36ac4c4fa514ff1c753ee15b` exited 0 and returned
the same SHA-256 as the pre-run independent capture:
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
Post-run metadata, allocation, hole location and marker were also rechecked.

State: `v11-release-exact-three-api-tail-passed; remaining-library-and-release-gates-open`
