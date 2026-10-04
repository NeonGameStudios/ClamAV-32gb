# R05 Sonic1 AlertExceedsMax structured-report revalidation — 2026-10-03

Task: `R05`, with the report repair shared by `R03`, `R04`, and `R10`.
This is targeted oversize reporting evidence; it is not a general 32-GiB
traversal, parser, production-database, or release qualification.

## Candidate and provenance

- Repository `ClamAV-32gb`, branch `largefile-roadmap-qualification`, commit
  `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`. The source handoff bound the
  dirty worktree as 160 porcelain rows, SHA-256
  `ff643f4cbcd6e107c53572f33fec745e5768468b8d7fe8c8899a6ad51551545d`.
- Git-less source manifest SHA-256
  `62bfd9df1d39f5a8081dcbd9458c50039f578c4f9bd694e9c2d017a8ad21a561`;
  deterministic package SHA-256
  `d298c08ba3f1f313e54da4d2c26bc9e456ab12ef19272e491bfda93dbba73421`
  (17,934,637 bytes). MCP-SSH transfer
  `transfer_7e56655ba082452685e527d1f1ca0c08` committed atomically with the
  matching checksum. The extracted source regenerated the same manifest
  (1,723 files). The sidecar binds commit, worktree state, package/manifest,
  transfer, and run IDs.
- Run `R05-sonic1-alertreport-v4-20261003-62bfd9df`, on Sonic1 via
  `sonic1-camera-key`, Linux x86-64, container
  `450e8d8f297ffb0d8ace2900b2802bfb2a6f47b63ea40d1e48d0168fd7a41a6c`, image
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Release CMake cache SHA-256
  `e0f80d7cd9e014384109b1ebb1fb936f1bd1159a2a75948e43543d579bdeec7a`.
  Fresh `clamscan`, `clamd`, and `check_clamav` targets built successfully;
  binary SHA-256 values are respectively
  `5d34e22c09de3786834ea5679cab81c3b64bba9c075e26ae03fe6e2c246fe6e7`,
  `205b5cebfd098294982dbd25834d9ec73e485730cfdfd4f8027d3611ad13209c`, and
  `11c6e22e201b0a00f7c7d87d6daa04949c034e913171893f7f68d21f6dc1a053`.
- The pinned `clam-sigutil` Git dependency was not available to Cargo offline.
  The existing Rust archive was reused only after verifying all 155 Rust and
  Cargo inputs byte-for-byte identical to the preceding candidate; archive
  SHA-256 `e2c62eac45cde9fd429cb561334ba6e7ebc7c291930a34a80bfeb6f281739ba2`
  (58,391,436 bytes). The generated Rust header was likewise reused after
  input identity verification (SHA-256
  `09bf3b01cb807c82dd69bbfebbcb0eb755635a9866da57ca7149cd893c470a15`). The
  C sources, executables, and test binary were freshly compiled/linked.
- Focused `ctest -R '^libclamav$'` passed 1/1 with `CK_RUN_SUITE=cl_suite` and
  `CK_RUN_CASE=cl_api` (20.89 s). The selected case includes
  `test_scan_report_promotes_enabled_exceeds_max_detection`.

## Materialized ClamScan boundary pair

The private non-matching `nevermatch.hdb` SHA-256 was
`0375814b8af4c38fdb2b0a7eef9b288e6fb08e8f8bdfbe718a657e57088050b6`.
ClamScan used `MaxFileSize=32G`, `MaxScanSize=64G`, and a fully allocated
regular input of exactly 34,359,738,369 bytes (32 GiB + 1). Allocation was
34,359,750,656 bytes. The fixture inode/mtime and full SHA-256
`e5ac6089ac04599810af19a2d93858c841e307037fa016f90efad197ec606720` were
unchanged before/after; no temp files remained. Both runs matched their
expected CLI exit status:

| `AlertExceedsMax` | Exit | Structured outcome |
|---|---:|---|
| `no` | 2 | `LIMIT_INCOMPLETE`, status 24, verdict 0, no alert; reason `Heuristics.Limits.Exceeded.MaxFileSize`. |
| `yes` | 1 | `DETECTION_TERMINATED`, status 0, verdict 3, exact `last_alert` and reason `Heuristics.Limits.Exceeded.MaxFileSize`; legacy output says `FOUND`. |

For both reports, parser/matcher/detector work and temporary bytes were zero;
the alert-enabled structured result now agrees with the CLI detection result.
The report SHA-256 values are `b6053cf63eaa75f5dcb7a7c272392c1b4877bd2075ea5bf4beac34f805beae05`
(off) and `4b54d3dfff0245b606a5ba87d0ac213deefc5f8169d438c5974e714fd25d1086`
(on). This boundary test does not establish parser traversal of the
oversized content.

## ClamD sparse FILDESREPORT pair

The strict `largefile_service_oversize.py` verifier passed in both modes on
fresh daemons using the same private HDB and 32-GiB `MaxFileSize`. Each probe
sent a sparse 34,359,738,369-byte descriptor through `FILDESREPORT`; allocated
bytes were zero, fixture metadata was stable, cleanup succeeded, and each
daemon returned PONG before and after and exited cleanly.

| `AlertExceedsMax` | Structured outcome |
|---|---|
| `no` | `LIMIT_INCOMPLETE`, status 24, verdict 0, no alert; exact MaxFileSize reason. |
| `yes` | `DETECTION_TERMINATED`, status 0, verdict 3, exact MaxFileSize alert and reason. |

Both per-mode validators exited 0. Report SHA-256 values:
`8e2aa4102ba293cf6a67c0666314fe6265362f73c69bf1a79433404fedc1cadc` (off),
`308ee09e4d65129a931c5f4fae471dffade5f932580b76dd944a179980634771` (on);
combined validated bundle SHA-256
`2dfa5da2965ea414f54973cc0b2e5d2f1671a02142cbda37cc3174231a622914`.
Run summary, configs, logs, and JSON evidence are retained on Sonic1 under
`/qualification/r05rpt-v4-62bfd9df/clamd-retry1/`; the sparse fixture was
removed and the temp directory is empty. The first config draft stopped at
startup because it supplied `off/on` instead of ClamD's required `no/yes`;
that attempt issued no probe and is kept separately at
`/qualification/r05rpt-v4-62bfd9df/clamd/`. The corrected, successful run is
the `clamd-retry1` evidence above.

At scan preflight `/tmp` had 214,557,982,720 free bytes versus 108,447,924,225
required; it had the same free space after the materialized pair. Available
memory was about 63.7 million KiB, swap was zero, and cgroup OOM counters
remained zero. The qualification volume had 71,034,130,432 free bytes; large
test input and temporary work stayed on `/tmp`.

## Fresh C ASan/UBSan counterpart

A separate current-source CMake build used GCC 12.2 with AddressSanitizer and
UndefinedBehaviorSanitizer at
`/tmp/clamav-r05-alertreport-v4-62bfd9df-c-asan-build`. Its CMake cache SHA-256
is `2bb5d546f1398d301bd558279a8caf820978a648d80e92381916876271ab0a25`. Fresh
`check_clamav`, `clamscan`, and `clamd` targets built successfully and link
`libasan` and `libubsan`. The focused `libclamav` `cl_api` test passed 1/1 with
leak detection and halt-on-error enabled; its `LastTest.log` SHA-256 is
`2f461fc35ba04ae10098be4c6a6116512e4898c922ee2af6d73597759fa22ca1`.

The instrumented ClamScan repeated the materialized 32-GiB-plus-one alerts-off
and alerts-on pair, matching the release report hashes above. The instrumented
ClamD repeated the sparse `FILDESREPORT` pair; the validated bundle SHA-256 is
`702d2f2d5b208c924682c856ddaffb35019461866d74cdfb38d819629d78d3b7`. Both
programs returned expected statuses, ClamD retained PONG health, and neither
run emitted sanitizer diagnostics. The ClamScan fixture's before/after SHA-256
remained `e5ac6089ac04599810af19a2d93858c841e307037fa016f90efad197ec606720`;
free space and temp-directory checks were unchanged. Evidence is retained on
Sonic1 under `/qualification/r05rpt-v4-62bfd9df/clamscan-c-asan/` and
`/qualification/r05rpt-v4-62bfd9df/clamd-c-asan/`.

The Rust static archive and header were verified and reused because the pinned
Git dependency was unavailable offline. They were not rebuilt with Rust
sanitizers, so these results instrument the C code and do not constitute Rust
sanitizer coverage.

## Exact materialized raw-library API edge

A separate, fully materialized 34,359,738,368-byte raw fixture placed
EDGE-LATE-MARKER at EOF-16. Its SHA-256 before and after the runs was
6b245dfdd4dbe54a274e44ceb5914d1f0a288b67bb867a6c5be79845a34c7360.
The inode was 11798295, mtime_ns 1790999873561691949, and allocated storage
was 34,359,746,560 bytes; SEEK_HOLE returned EOF. The registered
largefile_library_exact_32g test checked exact-tail detection through
cl_scanfile_ex2, cl_scandesc_ex2, and cl_scanmap_ex2.

Both builds used the same source manifest, 62bfd9df1d39f5a8081dcbd9458c50039f578c4f9bd694e9c2d017a8ad21a561.
Release check_clamav SHA-256 was
11c6e22e201b0a00f7c7d87d6daa04949c034e913171893f7f68d21f6dc1a053 and its
CMake cache SHA-256 was e0f80d7cd9e014384109b1ebb1fb936f1bd1159a2a75948e43543d579bdeec7a.
The C ASan/UBSan check_clamav SHA-256 was
7ba1efe93ed5b9db03f5eb23712aee70ced90ff1ad093f43017f32591370f5ad and its
CMake cache SHA-256 was 2bb5d546f1398d301bd558279a8caf820978a648d80e92381916876271ab0a25.
Leak detection and halt-on-error were enabled; UBSan also halted on error.

| Build | CTest result | Resource samples | Peak RSS / PSS | Swap / OOM | Conservative temporary-tree peak |
| --- | --- | ---: | ---: | ---: | ---: |
| Release | 1/1 passed, 1247.46 s | 10,786 | 122,284 / 114,871 KiB | 0 / 0 | 311,659,978 bytes |
| C ASan/UBSan | 1/1 passed, 1559.43 s | 10,925 | 316,552 / 309,152 KiB | 0 / 0 | 416,000,759 bytes |

The resource wrapper used unit_tests as its temporary root, so these small
temporary-tree peaks conservatively include static files in the test tree;
they are not a parser-spool measurement. Both cgroups reported zero OOM and
OOM-kill events. The C sanitizer LastTest.log reports one check, zero failures
and zero errors; stderr was empty. The Rust archive/header were reused after
their inputs were verified identical, so Rust code was not sanitizer
instrumented.

Release evidence is retained at
/qualification/r05-exact32g-v4-20261003-62bfd9df/release/:
test.log SHA-256 d73c6fbf7836b91e5f3777c7d0619c757fc986f2ee318add65ae2bb5877342d0,
resource TSV a4d28b9eb31b6629cd4c955fd643a4861c847930db26f6bbb45d9f30f90cf674,
and samples TSV 8c3ad7969cbcb63bfcaca96bca67ef591ea7a565bbe564d43dda5abfd6a7327f.
C sanitizer evidence is at
/qualification/r05-exact32g-v4-20261003-62bfd9df-asan/library-exact32g/:
test.log 71665cfe6116ff7ced858021f95c529b1a4274147c6ad228d0736577a047ba3b,
resource TSV 3be7526048ddb3268844cbf051a7ec474d6ccc474c4b4ef4fc1071ddff29ab6c,
samples TSV fb2d2f8a879f7cfd9622d4f7c70352f64888351aed7f044ce07afcb25c1aab35,
and LastTest.log 6a87bed6bee26a726084d195925baab22fd7a191393c86f6094cf5c0b2365e79.

This closes only the exact raw-library edge test for these three APIs. It
does not establish parser traversal, full ClamScan/ClamD ingress parity,
production-CVD behavior, or overall R05/release readiness. No capability was
promoted.

## Qualification boundary

This revalidates structured oversize reporting for a materialized ClamScan
boundary input and a sparse ClamD `FILDESREPORT` descriptor. It does not
qualify a full 32-GiB accepted scan, deep parser corpus, sanitizer/resource
matrix, other service ingress paths, production-CVD behavior, fanotify, or
release readiness. No capability was promoted; R05 and the overall roadmap
remain open.

State: `v4 build and targeted boundary regressions pass; Rust archive reused;
not release-qualified`.
