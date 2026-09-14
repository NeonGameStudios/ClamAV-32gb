# R08 current-source MSXML streaming empty-Base64 MaxFiles accounting — 2026-09-13

## Scope

The streaming MSXML Base64 path created a temporary output file for every
recognized Base64 element, but only invoked nested scanning when
`b64_saw_data` was set. An empty or whitespace-only element could therefore
skip descriptor admission, inclusive `MaxFiles` accounting, and cache-taint
propagation.

## Changes

- `libclamav/msxml_parser.c` now routes every created streaming Base64 spool
  through the existing callback or descriptor-admission path, including
  zero-byte decoded output.
- `unit_tests/check_clamav.c` adds a production-linked regression with the
  enclosing XML layer already consuming the only `MaxFiles` slot; an empty
  Base64 child must return `CL_EMAXFILES`, preserve the exact limit reason,
  and mark the input fmap non-cacheable.
- `tools/largefile_source_guards.sh` protects the new implementation and
  registered regression.
- The generated `docs/largefile-inventory.tsv` was refreshed after the test
  insertion.

## Verification

The retained `rust:1.97-bookworm` ARM64 Docker development container was
reused; no software was installed.

- Current-source Release `check_clamav` rebuilt successfully. The focused
  `CK_RUN_CASE=test_msxml_empty_base64_counts_toward_maxfiles` CTest passed
  `1/1` in `0.25` seconds.
- Current-source ASan/UBSan `check_clamav` rebuilt successfully. The same
  focused CTest passed `1/1` in `1.32` seconds with no sanitizer diagnostic.
- Retained Release test log:
  `/private/tmp/clamav-r08-msxml-empty-base64-maxfiles-release-20260913.log`,
  SHA-256
  `3c8ac81c2f784dd836b52e141d5535f5bc0cbf19dfec7991666329f75963babd`.
- Retained ASan/UBSan test log:
  `/private/tmp/clamav-r08-msxml-empty-base64-maxfiles-asan-20260913.log`,
  SHA-256
  `7edf9d474ea69051f98f1138989caafd22663cf3a81b521d1f827a613a7e6d19`.
- Full source-guard sweep passed, including the 602-capability map and
  zero-record acceptance schema. Retained log:
  `/private/tmp/clamav-r08-msxml-empty-source-guards-20260913.log`,
  SHA-256
  `de65d6080860c728e2ffe77d4fe22653d37ced2b806316b5d1ffac910e2ad735`.
- Snapshot freshness, regenerated inventory comparison, and `git diff --check`
  passed. The current source manifest has 1,697 entries and SHA-256
  `233628468afff59325eff18ebf20c1201483d60f7d3dd685935ee36431dde0bb`.
  The regenerated inventory SHA-256 is
  `15199b416df2909d40a65db971ce8f55f666f8f62b48d0c441106aaff97ed29d`.

## Qualification boundary

This is current-source ARM64 development evidence. It does not qualify the
MSXML/XML/OOXML/HWPML parser families' exact/materialized 32-GiB cases,
certified Linux x86-64, production CVD/service behavior, resource sidecars,
privileged fanotify, Sonic1, or final release readiness. No capability was
promoted. No usage reset, commit, push, or GitHub workflow action was used.

State: `development-verified; parser-family-qualification-open`.
