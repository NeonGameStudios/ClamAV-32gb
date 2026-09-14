# R03/R08 current-source HTML and MSXML MaxFiles revalidation — 2026-09-14

The current-source Release aggregate exposed five real MaxFiles regressions
behind the new empty-child coverage. HTML normalization returned a generic
`CL_EPARSE` instead of preserving the nested `CL_EMAXFILES` result. The
direct MSXML regressions used a zeroed engine/context, so they did not model
the compiled engine, recursion layer, or shared configuration used by the
production admission path. Both issues are corrected without changing the
release boundary.

## Changes

- `libclamav/scanners.c` now propagates any non-success nested limit result
  from HTML normalization, including `CL_EMAXFILES`, `CL_EMAXSIZE`, and
  related fail-visible limit results.
- The four direct MSXML MaxFiles regressions now initialize a compiled engine,
  shared `dconf`, recursion layer, and enclosing-layer file count before
  exercising the streaming and legacy parser paths.
- The generated `docs/largefile-inventory.tsv` was refreshed and verified
  byte-for-byte against `tools/largefile_inventory.sh`.
- The temporary isolated diagnostic TCase was removed; no
  `isolated_repro` registration remains.

## Source and build identity

- Source manifest: 1,697 entries,
  SHA-256 `ec37159c793ad0a9b41589a54baf4c8533ca95fd32935b5d79093bc7f955cbfb`.
- Inventory SHA-256:
  `899f0648d12c0de05997fc530d220a52c8de971ff36ff270a2a0082e192a8a36`.
- Existing ARM64 Docker container:
  `clamav-current-rust-build-20260911` (`rust:1.97-bookworm`).
- Release build `/tmp/clamav-release-current-20260913`:
  CMakeCache SHA-256
  `fac1d0a5d7867e5203daa614e2bc34322b3e044aaa8e698c191d10019a518fe1`;
  `check_clamav` SHA-256
  `8bda4e47d364bdad1863e83ebac4384557814d326ea70dbba90d9411af23e6d3`.
- ASAN/UBSAN build `/tmp/clamav-asan-current-20260912`:
  CMakeCache SHA-256
  `0b462671d850a78c28da47346f8718957d5a1fef918373723d62a3f111e98654`;
  `check_clamav` SHA-256
  `e3fc28f5d87cca9368e08c0e3ff1a01c3f78e114bf592d099f6c4a46c7345190`.
- Werror build `/tmp/clamav-werror-fixed-20260914`:
  CMakeCache SHA-256
  `eee33040da10adbc729adb35a7716094cd4c483d9cede64fdf5be4538206083a`.

## Verification

- Release `libclamav` aggregate: 2,942 checks, 0 failures, 0 errors, passed
  in 126.33 seconds.
- Complete configured current-source Release CTest suite: 28/28 tests passed
  in 196.47 seconds; retained log SHA-256
  `cf7b8e435c66ad99dffd4cbd64e8fec56fd087c95c00347443c07fd6344a231b`.
- Release direct Check runs: `html` 14/14 and `msxml` 14/14.
- ASAN/UBSAN direct Check runs: `html` 14/14 and `msxml` 14/14, with no
  AddressSanitizer, UndefinedBehaviorSanitizer, LeakSanitizer, or runtime
  diagnostic.
- Complete existing `ENABLE_WERROR=ON` build: exit 0 across all configured
  library and application targets.
- `sh tools/largefile_source_guards.sh`: passed; all 604 capability rows
  validated.
- Snapshot freshness, acceptance map (604 capabilities), empty record schema,
  inventory comparison, and `git diff --check`: all passed.
- `sh tools/largefile_release_readiness.sh --status`: expected exit 1 with
  604 total, 0 qualified, 147 bounded, 443 pending, 14 allowlisted
  unsupported, and 590 release-blocking rows.

## Qualification boundary

This is current-source ARM64 development evidence. No capability was
promoted. Certified Linux x86-64, exact/materialized 32-GiB runs, production
CVD/service evidence, measured resource and privileged fanotify evidence,
Sonic1 verification, independent format-8 fixtures, complete
capability-specific records, and final release review remain open. The
deferred branch/history consolidation and historical-PII purge remain listed
in `wishlist.md`.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
