# Task receipt: R13 process-tree service resource measurement — 2026-09-12

## Scope

The service qualification runner previously sampled only clamd's own
`/proc/<pid>/status` `VmRSS`. That was not sufficient for the roadmap's
resource contract because queued clamdscan clients, streaming helpers, and the
milter harness can be active at the same time. This slice makes the producer
and verifier require a combined process-tree RSS measurement.

## Changes

- Added `tools/largefile_procfs_tree_rss.sh`, which reads Linux procfs status
  records, follows `PPid` descendants from every active workload root, sums
  `VmRSS` once per PID, and returns the measured RSS and process count.
- Registered clamd, clamdscan, serial-queue clients, parallel clients, and the
  milter harness as active measurement roots. Descendant roots are de-duplicated
  by the sampler.
- Added explicit service-summary markers for the procfs tree sampler and the
  process count at the measured peak.
- Made `largefile_service_evidence_check.sh` reject daemon-only or otherwise
  unidentified RSS evidence.
- Added a real parent/child sampler regression and registered the service
  evidence verifier in CTest.

## Verification

All commands below used the existing `clamav-current-rust-build-20260911`
Linux ARM64 development container, with source mounted at `/src` and the
existing Release build at
`/tmp/clamav-release-current-20260912`:

- `sh tools/largefile_procfs_tree_rss_test.sh` — passed; the test observed the
  root and child, and confirmed duplicate descendant roots are not counted
  twice.
- `sh tools/largefile_service_evidence_check_test.sh` — passed.
- Focused CTest — 5/5 passed and exited 0:
  `largefile_source_guards`, `largefile_runtime_evidence_check`,
  `largefile_service_evidence_check`, `largefile_acceptance_case_schema`, and
  `largefile_procfs_tree_rss`.
- Retained CTest log:
  `/private/tmp/clamav-r13-process-tree-focused-ctest-final.log`, SHA-256
  `993b7414bee0d78e319d0485e916093704fa2da6bb5cfc006f8e8fa1beadc44b`.
- Current source manifest SHA-256:
  `7ed2dc136662b3a8b86ed0727f720d007dfd47cef6862fe4109b078c941594c9`.
- Current tracked inventory remains 44,670 lines, SHA-256
  `6b965f6fd0c565940b580a44f7d5564b8bbe3a3e4de17b2a4b629ad9a68e0813`.
- `git diff --check` completed without a diff error; Git reported only its
  existing CRLF normalization warnings for unrelated files.

After registering the new controls, the complete current-source CTest set was
rerun in bounded slices: 3/3 core library/daemon tests, 12/12 large-file
controls and milter tests, and 3/3 CLI utility tests. Every slice exited 0.
The retained logs are:

- `/private/tmp/clamav-r13-process-tree-matrix-slice1.log`, SHA-256
  `6cbcf776d2ef8950483247b511fcd04b6a795f3b6134dbe61d5e9a75473fab26`.
- `/private/tmp/clamav-r13-process-tree-matrix-slice2.log`, SHA-256
  `9960ae28150aceaa2ce32306a5de96652d7eb87c7a508bbbae57a13143d5f322`.
- `/private/tmp/clamav-r13-process-tree-matrix-slice3.log`, SHA-256
  `04e7224ae07fa02946fa42c23aad1a3a5aa9f65b609a39b8944273bf13d66890`.

The final post-sample focused CTest rerun also passed 5/5 and exited 0. Its
retained log is `/private/tmp/clamav-r13-process-tree-focused-final.log`,
SHA-256 `8bb6c593300dccb04f64767c5116532c922ad9bc8d7e896df894470012730057`.
The final `git diff --check` exited 0; only existing CRLF normalization
warnings were emitted.

## Qualification boundary

This is producer/verifier development evidence only. No full-size service
qualification was run, and this does not establish certified Linux x86-64,
PCRE phase residency, PSS/swap/page-fault evidence, production-CVD, Sonic1,
fanotify permission, sanitizer-parity, or release readiness. Those roadmap
requirements remain open.
