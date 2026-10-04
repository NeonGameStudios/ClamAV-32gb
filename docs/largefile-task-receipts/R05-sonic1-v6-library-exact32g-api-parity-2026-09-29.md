# R05 Sonic1 v6 exact-32-GiB library API parity — 2026-09-29

## Scope and source/fixture identity

This receipt covers the current v6 candidate's fully materialized exact
32-GiB **raw** fixture through `cl_scanfile_ex2`, `cl_scandesc_ex2`, and
`cl_scanmap_ex2` in one registered library qualification test case per
build. It is not the complete ingress matrix or release qualification.

The authorized runner was `sonic1` / `sonic1-camera-key`, using pinned
container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
with image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The read-only `/ram/edge-stable.bin` fixture is 34,359,738,368 bytes,
has at least that many allocated bytes (67,108,880 512-byte blocks), and
held inode 8149459 and mtime 1790047133 before and after the scans.
Independent bounded reads verified `EDGE-LATE-MARKER` at byte offset
34,359,738,352 (EOF minus 16). Managed full-file hashes before and after
both test runs, jobs `job_bd579c11d4504584b2e2724715640c1e` and
`job_6b3a38888aa54795a0a795715241bb33`, matched SHA-256
`98d5f7e2f73850de7a584ee5c5c6f7f109806b6bb80f146e6619046d5f2a281d`.

The frozen v6 source-package SHA-256 is
`6a886cf5269cda75c2e8f300cb0dd3772592b2a19ffd29c7cf5a31d272652987`;
transfer `transfer_26b9fdda6e42413aa3261159939562fa` and its extracted
source-content manifest are detailed in the v6 clean OneNote receipt.
Both library cases copied that source manifest, SHA-256
`c19b0777b9580611ec879bdbfb2740621aaf8bdbcc9f0a1f1189415be9c8fe5b`.
The copied Release `check_clamav` / `CMakeCache.txt` SHA-256 values are
`c3aafbf6d4b5dd50e3c3f01a1ed3fe3b0947683c750ed04bfa6d7f43183892d1` /
`c9e1473effc653f8e63ca8631e5b8954256281fd9fc84ee4599f383e7a2c5f00`;
C ASan/UBSan values are
`5429385655f99de8ad979bb3411e9d7c0f557a7bb91642705a2f50eec89b0d57` /
`036acc0b132d131dd8095372b82209d539815c2e44c0c454157aae1e218fba66`.

## Execution and assertions

The v6 CMake configuration explicitly enabled
`ENABLE_LARGE_FILE_QUALIFICATION_TEST=ON`; `ctest -N` registered
`largefile_library_exact_32g`. To capture a case-private temporary tree
and full process-tree samples, each job directly invoked that registered
`check_clamav` binary with its `cl_suite` / `largefile_qualification`
selection and CTest-discovered source/build/library/certificate environment.
It was not invoked through the `ctest` frontend. The Release run used the
test's 900-second large-file timeout; C sanitizer set `T=1800` for its
three scans. The managed job limits were 1,800 and 2,700 seconds. Both
remain below the PLAN's four-hour scan deadline. The sanitizer run set
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1` and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.

The source test first checks the fixture's regular-file, exact-size,
allocated-block, no-hole-before-EOF and exact-tail-marker conditions. It
then scans the same file with all three public APIs. For **each** API it
requires `CL_VIRUS`, the strong-indicator verdict, exact alert
`LargeFile.Library.32G.UNOFFICIAL`, report status `CL_VIRUS`, completion
`DETECTION_TERMINATED`, a scanner-reported alert offset equal to
34,359,738,352, `CL_TYPE_BINARY_DATA`, exact root size, matcher work
reaching the edge, and the configured 32/64-GiB limits. Passing the one
Check case therefore requires all three API assertions to pass; the
console summary alone does not enumerate the three calls.

| Observation | Release | C ASan/UBSan |
| --- | ---: | ---: |
| Managed test job | `job_fe7a0aaf75bd436a871d3bd3eb1fb1b0` | `job_b0f22c17552b4739b09e37ef49bb18dd` |
| Job exit / Check result | 0 / 1 check, 0 failures, 0 errors | same |
| Process-tree samples | 448 | 773 |
| Peak RSS / PSS | 103,124 / 100,320 KiB | 293,616 / 290,905 KiB |
| Sampled temp-tree / swap / OOM / OOM kills | 0 / 0 / 0 / 0 | same |

An independent read-only verifier checked each copied source, test-binary
and config hash against its resource row; the exact case identity;
consecutive sample sequence, row sample count and RSS maximum; the passing
Check summary; zero sampled swap/OOM; and empty case-private temporary
directories after completion. Both managed jobs captured zero stderr
bytes. The container's post-run `memory.events` reported `oom=0` and
`oom_kill=0`; `/proc/swaps` listed no active swap. Zero *sampled* temporary
peak is not a claim that the short-lived test signature was never written:
the process reported write I/O and the private directory was empty after
the test. Both runs used the same frozen fixture and v6 source; only the
Release versus C sanitizer build differed.

| Retained artifact | Release SHA-256 | C ASan/UBSan SHA-256 |
| --- | --- | --- |
| `provenance/test.log` | `d525cda19cc764985f224c11ea01db342bb1258569ce944ddb3d9e53c26f3197` | `f70bc2f0c094e2b772e791e7cba424b34d46ad7ce4d8f5f30d33d1945ff6c195` |
| `provenance/acceptance-case-resources.tsv` | `e84a6d7dee1276aa28a37ed4fb7b783cc98640634da6d2d834694c0d7c6128d4` | `92ea436474e3f4503b50d3bf718ed450c04a6892d1ab4d4facd9382f724fb168` |
| `provenance/samples.tsv` | `1ce34982b4e4645e566be754a8b47ab5dd90664f05cf04285c503d03acc5bd87` | `2e0566bd8e78b3830179bf7ae14602b9759007c75ca79c2b3c5ab3875f229b45` |

Evidence roots:
`/qualification/r05-v6-library-exact32g-20260929-release` and
`/qualification/r05-v6-library-exact32g-20260929-asan`. These results do
not prove staged stdin/INSTREAM, clamd/clamdscan, milter, on-access,
production-CVD, parser-family, Rust-source-sanitizer, or final release
qualification. No software, usage reset, GitHub push, or GitHub workflow
was used.
