# R05 Sonic1 v8 exact-32-GiB library API qualification — 2026-09-29

## Scope and provenance

This tests the frozen v8 candidate's registered
`largefile_library_exact_32g` case, which requires a fully allocated
34,359,738,368-byte regular file, the EOF-minus-16 marker, and exact
`CL_VIRUS`/strong-indicator/report/offset results separately from
`cl_scanfile_ex2`, `cl_scandesc_ex2`, and `cl_scanmap_ex2`. It is not the
whole ingress, parser, production-CVD, or release matrix.

Sonic1 profile `sonic1-camera-key` passed the live connection check.
The pinned container is
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The v8 archive transfer, remote manifest regeneration and coherent
Release/C ASan/UBSan builds are detailed in the v8 R12 raw ClamScan
receipts. The source manifest SHA-256 is
`f71a59692fd63357ba6f1ff362275cfadddfd20f6f01ac8b3edc5cb9ec99e723`.
Both v8 builds previously passed 32/32 non-edge CTests. `ctest -N -V`
confirmed the exact test is registered in each coherent v8 build with
the v8 source and signing-certificate paths. The copied Release
`check_clamav` and CMake cache hash to
`901bc579a9d58cc46bb5323688e8d8a5cb3991a0c1a43f83d422c447890b1abb`
and `1ca43701cd73d194a326466578027445edb4dda5c0fe48332672d41ce8f4bde3`;
the sanitizer counterparts hash to
`2b6bd32eb8d74fd9460bedced6864ccb8b79fbe23be676d40dd394a32be497ff`
and `df647e505b1ec18717e4d251bc1f5cb3500353536fd910a764aa87281fbbe07d`.

The fixture `/ram/edge-stable.bin` is read-only and root-ext4-backed,
not tmpfs. Pre- and post-Release stat showed size 34,359,738,368,
67,108,880 allocated 512-byte blocks, inode 8149459 and mtime
1790047133. Previous independent full-file SHA-256 and v8 scanner logs
give `98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.
The source test itself checks the allocated-block count, `SEEK_HOLE`,
EOF marker, and the scan result for each of the three APIs.

## Release result

Managed job `job_265dfa391ff541b0a1a42cd1d139925e` used the v8
resource wrapper, the registered CTest case, a case-private LV-backed
temporary directory, the exact fixture path, `T=900`, and 100-ms
requested process-tree samples. It exited 0 after 616.74 seconds.
CTest reported `Checks: 1, Failures: 0, Errors: 0` and 1/1 passed.
The wrapper retained 5,772 ordered samples and a resource row with
RSS/PSS peaks 119,912/112,724 KiB, 8,192-byte sampled temporary peak,
and zero sampled swap, OOM and OOM kills. An independent read-only
verifier checked the test outcome, copied source/binary/cache hashes
against the row, all consecutive sample numbers and increasing
timestamps, stable root PID inclusion, trace/row RSS peak equality,
bounded temporary usage, and empty post-run temporary directory; it
exited 0.

Evidence root: `/qualification/r05-v8-library-exact32g-20260929-release`.

| Artifact | SHA-256 |
| --- | --- |
| `provenance/test.log` | `6cb3b9d1f2df678b46dfcfad447be0fbd1a57a185deca2e7102e7e51fa297239` |
| `provenance/acceptance-case-resources.tsv` | `ba60c6eb11478461fdc607a6329791bd9e362ebbf45b77d770a884446295a7b6` |
| `provenance/samples.tsv` | `7318031152d081df15e0ac2b94a9ef3bb42c89b9a9dc216c3faeef2388b64b61` |

## C ASan/UBSan parity

The separate C ASan/UBSan exact-three-API job
`job_6513fa43cfc940629a543f58ff666cc2` used a fresh case-private
evidence root, `T=1800`, leak detection and UBSan halt/stacktrace
options. It exited 0 after 1031.22 seconds. CTest reported
`Checks: 1, Failures: 0, Errors: 0` and 1/1 passed. No ASan, LSan or
UBSan diagnostic appeared in the retained test log.

The wrapper retained 8,097 ordered process-tree samples. Its row
records RSS/PSS peaks 313,908/306,719 KiB, an 8,192-byte sampled
temporary peak, and zero sampled swap, OOM and OOM kills. An independent
read-only verifier rechecked the test outcome, sanitizer log, case-local
source/binary/cache hashes, every sample number and timestamp, stable
root PID inclusion, trace/row RSS peak equality, bounded temporary
usage and empty post-run temporary directory; it exited 0. The fixture
size, allocation, inode and mtime remained unchanged after the
sanitizer run. Independent post-run full-file hash job
`job_2747b272711a4c7bad8a732b61a4181f` exited 0 and returned
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`,
matching the prior full-file oracle and v8 scanner logs.

Evidence root: `/qualification/r05-v8-library-exact32g-20260929-asan`.

| Artifact | SHA-256 |
| --- | --- |
| `provenance/test.log` | `6226a715c8866ba8a65e9cf0a8221fe4bde21ea1689d9d1af7a3729abf53638a` |
| `provenance/acceptance-case-resources.tsv` | `80663a96bf21c546cea4bd8f2bb7c82a4660dc5ea69cbb17a64f463992cb267c` |
| `provenance/samples.tsv` | `a4ccb1d7207ef2e4d8dd50cc6198b06cd641dd1140765323f6918eb914dc3257` |

This gives current-v8 Release/C-sanitizer exact-size proof for the
three modern library APIs only. It does not qualify all required clean,
limit, and operational-failure cases, other ingress families, the
disk-spooled OneNote parser, production-CVD canary, or final release
readiness. No capability was promoted.
