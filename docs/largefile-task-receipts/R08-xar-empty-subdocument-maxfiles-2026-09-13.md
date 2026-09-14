# R08 current-source XAR empty-subdocument MaxFiles accounting — 2026-09-13

## Task identity

Parent milestone: R08.
Capability: `library:xar-empty-subdocument-maxfiles`.
Starting HEAD: `8e837b88c89874b180a1a25f22d287f7d6be29db`; the working tree was already dirty and no clean qualification candidate was claimed. Current source manifest: 1,697 entries, hash `b2d46417e05346dfaffb5a6576a98f288204210cf0ed20163626dbcf2b5b5b6e`.

## Observed gap

`xar_scan_subdocuments()` created a temporary spool for a recognized `<subdoc>` but skipped descriptor admission whenever the serialized body was empty, including a self-closing element. That allowed a logical child to bypass inclusive `MaxFiles` accounting and cache taint. The pre-fix current-source control returned clean (`ret == 0`) where `CL_EMAXFILES` was required.

## Changes

- `libclamav/xar.c`: retain the empty spool through rewind and `cli_magic_scan_desc_type_reserved`; keep the empty-child diagnostic.
- `unit_tests/check_clamav.c`: add `test_xar_empty_subdocuments_count_toward_maxfiles`, registered in `xar_subdoc`; direct context starts with the enclosing XAR admitted and `MaxFiles=2` so the recognized empty child must fail visibly.
- Add capability/case-map rows and source guards.

## Verification

- Retained `rust:1.97-bookworm` ARM64 Docker validation container; no software installed.
- Current-source Release `check_clamav` rebuilt successfully after the final test source.
- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=xar_subdoc T=1200` Release: 2/2 checks passed; log SHA-256 `2c3b12b8e90a10f0b526b41b0ff65233b24735cea4ec2a5b2c623c3988d97017` (`/private/tmp/clamav-r08-xar-empty-subdoc-release-20260913.log`).
- The same ASAN/UBSAN command: 2/2 checks passed; no sanitizer diagnostics; log SHA-256 `2c3b12b8e90a10f0b526b41b0ff65233b24735cea4ec2a5b2c623c3988d97017` (`/private/tmp/clamav-r08-xar-empty-subdoc-asan-20260913.log`).
- Full source guards passed; log SHA-256 `2f6ba5bc24b791e6724a70ff70fefdc3f3ef3debd7327644c694d4a3c2b35e44` (`/private/tmp/clamav-r08-xar-empty-subdoc-source-guards-20260913.log`).
- Snapshot freshness, regenerated-inventory comparison, acceptance case map (603 capabilities), record schema check (0 records), and `git diff --check` passed.
- Current readiness status: 603 total, 0 qualified, 147 bounded, 442 pending, 14 allowlisted unsupported, 589 blocking; readiness remains blocked.

## Qualification boundary

State: development-verified; parser-family-qualification-open.
No capability promoted. Certified x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify, Sonic1, independent format-8, complete XAR corpus, and final release evidence remain open. No commit, push, GitHub workflow action, software installation, or usage reset.
