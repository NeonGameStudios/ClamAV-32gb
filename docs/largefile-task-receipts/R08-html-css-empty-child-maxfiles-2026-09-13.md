# R08 current-source HTML CSS empty-child MaxFiles accounting — 2026-09-13

## Scope

The shared Rust reader-to-temporary-spool helper returned clean without
calling descriptor admission when a decoded child contained zero bytes. That
allowed an extracted CSS `data:image/...;base64,` child to bypass the
inclusive `MaxFiles` budget and cache-taint propagation.

## Changes

- `libclamav_rust/src/scanners.rs` now sends empty reader output through the
  same descriptor admission path as non-empty output.
- `unit_tests/check_clamav.c` adds a production-linked HTML regression with a
  single-slot `MaxFiles` budget. The HTML root consumes the slot, and its
  empty decoded CSS image must return `CL_EMAXFILES` and mark the map
  non-cacheable.
- `tools/largefile_source_guards.sh` protects the shared helper invariant and
  the registered regression.
- The generated `docs/largefile-inventory.tsv` was refreshed after the test
  insertion.

## Verification

The existing retained `rust:1.97-bookworm` ARM64 Docker development
container was reused; no software was installed.

- Current-source Release `check_clamav` rebuilt successfully. The focused
  `CK_RUN_CASE=test_html_css_empty_image_counts_toward_maxfiles` CTest passed
  `1/1` in `0.34` seconds.
- Current-source ASan/UBSan `check_clamav` rebuilt successfully. The same
  focused CTest passed `1/1` in `1.26` seconds with no sanitizer diagnostic.
- Retained Release test log:
  `/private/tmp/clamav-r08-html-css-empty-maxfiles-release-20260913.log`,
  SHA-256
  `4e123fc8cb4368d84a2d0bab58b54b36caf9a7ac1b3d41f1079d06ffb1510b5b`.
- Retained ASan/UBSan test log:
  `/private/tmp/clamav-r08-html-css-empty-maxfiles-asan-20260913.log`,
  SHA-256
  `eb8d5af8f1be516629e703020b80cda16b2e372e435a6028533a19d69cc6608a`.
- Full source-guard sweep passed, including the 602-capability map and
  zero-record acceptance schema. Log:
  `/private/tmp/clamav-r08-html-css-empty-source-guards-20260913.log`,
  SHA-256
  `0b86c74b1fd33ec5d458177c145e5c2bc2f7683d4ac7590f2f11fd181ecd932c`.
- Snapshot freshness, regenerated inventory comparison, and `git diff --check`
  passed. The current source manifest has 1,697 entries and SHA-256
  `23ba6cd8f4d05df7348bececdfe18b902f5f3e8026b8739878a2c9fbaa06e461`.
  The regenerated inventory SHA-256 is
  `1fc7442202e9a306a002d28cc4091aab823470331d42bb6dffe746c4058f7753`.

## Qualification boundary

This is current-source ARM64 development evidence. It does not qualify the
HTML parser's exact/materialized 32-GiB cases, certified Linux x86-64,
production CVD/service behavior, resource sidecars, privileged fanotify,
Sonic1, or final release readiness. No capability was promoted. No usage
reset, commit, push, or GitHub workflow action was used.

State: `development-verified; parser-family-qualification-open`.
