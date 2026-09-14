# R08 matcher and YARA current-source revalidation — 2026-09-13

## Scope

Run the production-linked matcher feature cases against the current source in
the disposable ARM64 Linux Docker builds. The matcher case covers AC, BM,
PCRE, logical-signature, hash, bytecode compatibility, offset and allocation
boundaries; the YARA case covers instruction-stream admission, arena
relocations, VM faults, matcher-work accounting, and deadline behavior.

## Provenance

- Source root: `/src`, mounted from
  `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- Source manifest: `4ff6260cf89396c0d4a5c96c889b89558cab599e33c4b26976921ce629749efc`
- Release build: `/tmp/clamav-release-current-20260913`
- ASan/UBSan build: `/tmp/clamav-asan-current-20260912`
- Test binary: each build's `unit_tests/check_clamav`
- CVD certificate binding: `/src/unit_tests/input/signing/verify`
- Runner: existing disposable `rust:1.97-bookworm` ARM64 Linux container

## Results

The `matchers` suite was run with `CK_RUN_CASE=matchers` and `CK_RUN_CASE=yara`
in each build:

| Case | Release | ASan/UBSan |
| --- | ---: | ---: |
| `matchers` | 51/51 | 51/51 |
| `yara` | 21/21 | 21/21 |
| **Total** | **72/72** | **72/72** |

All four invocations exited successfully with zero failures and zero errors.
The ASan/UBSan invocations emitted no sanitizer, leak, undefined-behavior, or
runtime-error diagnostics.

## Qualification boundary

This is current-source ARM64 development evidence only. It does not replace
the complete matcher/YARA corpus, exact/materialized 32-GiB fixtures,
certified Linux x86-64 Release and sanitizer runs, production CVD/service
evidence, resource and fanotify evidence, Sonic1 evidence, independent
format-8 bytecode evidence, or final release qualification. No capability
status was promoted.
