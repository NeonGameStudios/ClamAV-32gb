# R08 current-source MSXML self-closing empty-child MaxFiles accounting — 2026-09-13

## Scope

The legacy MSXML reader returned immediately for recognized self-closing
elements before callback/Base64 child admission. Consequently, a logical
`<bindata/>` or callback child could bypass inclusive `MaxFiles` accounting and
cache taint.

## Changes

- Added a shared `msxml_scan_empty_child()` helper in
  `libclamav/msxml_parser.c` that creates a bounded temporary spool, performs
  time-limit checks, invokes either the callback or descriptor admission,
  closes/unlinks the temporary file, and merges cleanup failures.
- The legacy self-closing branch now uses that helper for recognized callback
  and Base64 elements.
- Added production-linked regressions for self-closing Base64 and callback
  children, with the enclosing XML layer already consuming the single allowed
  file slot.
- Added source guards for the helper, self-closing admission, and both test
  registrations; refreshed the current-source inventory.

## Verification

- Used the retained `rust:1.97-bookworm` ARM64 Docker build environment; no
  software was installed.
- Rebuilt current-source `check_clamav` in both Release and ASAN/UBSAN builds.
- Four focused Release cases passed 1/1 each:
  `test_msxml_empty_base64_counts_toward_maxfiles`,
  `test_msxml_empty_callback_counts_toward_maxfiles`,
  `test_msxml_self_closing_base64_counts_toward_maxfiles`, and
  `test_msxml_self_closing_callback_counts_toward_maxfiles`.
- The same four ASAN/UBSAN cases passed 1/1 each with no sanitizer diagnostic.
- Release log SHA-256 values:
  - `test_msxml_empty_base64_counts_toward_maxfiles`: `5e55d0f079a85221bfba833197f9a42b298d0387dafc18b578ecbca7af5fd7`
  - `test_msxml_empty_callback_counts_toward_maxfiles`: `6cd3b31ccf573b1a27225fe630f804d81ee7b7eaccc4568a5d182853d2c051ae`
  - `test_msxml_self_closing_base64_counts_toward_maxfiles`: `acb5ded52db402801bb028f69ed0cb9db54b74b4633804dab674f5690840ef4a`
  - `test_msxml_self_closing_callback_counts_toward_maxfiles`: `6cd3b31ccf573b1a27225fe630f804d81ee7b7eaccc4568a5d182853d2c051ae`
- ASAN/UBSAN log SHA-256 values:
  - `test_msxml_empty_base64_counts_toward_maxfiles`: `664b0fb2583c82431df1415f0037111b609a4f496e13b2a54084e4f69566dcd6`
  - `test_msxml_empty_callback_counts_toward_maxfiles`: `27bed0a88e73b96b377b6f4efe04bc37e65573653c7af9d0b47f5c27b9e67ce0`
  - `test_msxml_self_closing_base64_counts_toward_maxfiles`: `27bed0a88e73b96b377b6f4efe04bc37e65573653c7af9d0b47f5c27b9e67ce0`
  - `test_msxml_self_closing_callback_counts_toward_maxfiles`: `27bed0a88e73b96b377b6f4efe04bc37e65573653c7af9d0b47f5c27b9e67ce0`
- The full current-source guard sweep passed. Its retained log is
  `/private/tmp/clamav-r08-msxml-self-closing-source-guards-20260913.log`,
  SHA-256 `de65d6080860c728e2ffe77d4fe22653d37ced2b806316b5d1ffac910e2ad735`.
- Snapshot freshness, regenerated-inventory comparison, and `git diff --check`
  passed. The current-source manifest contains 1,697 entries and has SHA-256
  `b771ad304a84cf37a65bb5e9d440da0a579bcc38eba257339884acf1a0b8b233`.
  The refreshed inventory has SHA-256
  `b0f04331aef8476c950f1a0c0702cdfbca2bf09239a5c74f5439e97cf7ffa9e4`.

## Qualification boundary

This is development verification on ARM64 only. No capability was promoted.
Certified Linux x86-64, exact/materialized 32-GiB, production CVD/service,
resource and privileged fanotify, Sonic1, independent format-8, and final
release qualification remain open.

State: development-verified; parser-family-qualification-open.

No commit, push, GitHub workflow action, software installation, or usage reset
was performed.
