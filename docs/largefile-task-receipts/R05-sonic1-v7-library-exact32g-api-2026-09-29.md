# R05 Sonic1 v7 exact-32-GiB library API regression — 2026-09-29

This is a current-v7 Release regression of the registered
`largefile_library_exact_32g` test, not the complete ingress matrix or a
release qualification. It exercises one fully materialized exact-32-GiB
raw fixture through `cl_scanfile_ex2`, `cl_scandesc_ex2`, and
`cl_scanmap_ex2`. The `check_clamav.c` case requires the expected
`CL_VIRUS`/strong-indicator result, exact scanner-reported EOF-minus-16
alert offset, report completion/type/size, and configured 32/64-GiB
limits for **each** API before its single Check assertion can pass.

The authorized runner was `sonic1` / `sonic1-camera-key`, using pinned
container `c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
and image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The fixture was `/ram/edge-stable.bin`, mounted read-only in the container.
Despite the `/ram` name, `df -T` identifies its actual backing store as
root **ext4**, not tmpfs; this run did not claim memory-backed input.
Before and after the test, the fixture had size 34,359,738,368 bytes,
67,108,880 allocated 512-byte blocks, inode 8149459, and mtime
1790047133. Its exact EOF-minus-16 marker was established in the earlier
v6 library receipt; the unchanged fixture was read-only during this run.
Managed post-run full-file SHA-256 job
`job_d5dcf4ea0c24493f8a1718e4847ac48c` exited 0 and returned
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`,
matching both full-file hashes from the v6 API receipt.

The frozen v7 source package, transfer and manifest regeneration are
recorded in `R13-sonic1-v7-bounded-onenote-sampler-2026-09-29.md`.
The case-local source manifest, `check_clamav` binary and CMake cache
SHA-256 values are, respectively,
`72bb5de991f23098030c27f666578740b1ca74eaf0e7b3e1b9938735a70b2ebb`,
`e9b6ae283b653e5ec6a93c66d2e2c858f70a5e38db1396da6664b32a4968391d`,
and `c312a602270217130f04e1a11e12bb4c5883dd58b5b5ee1b78037c3768a90992`.
`ctest -N -V` confirmed registration and the exact source/build/certificate
environment before the run. The v7 Release non-edge suite had already
passed 32/32.

Managed job `job_933d6669839e4a818a06a50e6b0a7e6c` ran that registered
CTest case with `CLAMAV_LARGEFILE_FIXTURE=/ram/edge-stable.bin`, a
case-private `TMPDIR`, and `T=900`, wrapped by the v7 process-tree
resource sampler. It exited 0 after 611.01 seconds. CTest reported
`Checks: 1, Failures: 0, Errors: 0` and `1/1` passed; the wrapper retained
5,753 ordered samples. The resource row reported 122,556/115,366 KiB
RSS/PSS peaks, 8,192 bytes sampled temporary peak, and zero sampled swap,
OOM and OOM kills. The case-private temporary directory was empty on exit.
The qualification LV still had 33,191,886,848 bytes free. The copied
source/binary/config hashes matched the row. The raw API path did not
create the large disk spool that makes the v7 OneNote full-size rerun
unsafe with the current LV headroom.

| Retained artifact | SHA-256 |
| --- | --- |
| `provenance/test.log` | `0244a3bee463e65057af933b4a89f21053fba1f73b1d5c49c36bbcb20de61a71` |
| `provenance/acceptance-case-resources.tsv` | `be36c101b68a0ea31cf6cf267bda09df68c7bde1a8f443164c3bd7bab6f423c4` |
| `provenance/samples.tsv` | `972f9cc56a439a2083c0aa4f2c0001527f8126cbe4c2d7e943e748e197548b42` |

Evidence root: `/qualification/r05-v7-library-exact32g-20260929-release`.
This case does not establish v7 C ASan/UBSan parity, disk-spooling OneNote,
stdin/INSTREAM, clamd/clamdscan, milter, on-access, production-CVD, or
final readiness. No capability was promoted; no software, usage reset,
GitHub push, or GitHub workflow was used.
