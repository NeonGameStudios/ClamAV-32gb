# R08 parser-family current-source revalidation — 2026-09-13

## Scope

Re-run a focused parser-family slice against the current source tree in the
disposable ARM64 Linux Docker build. The slice covers ARJ compression and map
admission, BinHex, MyDoom, BZip2 map/core paths, CAB SFX, SIS structure/member
paths, and InstallShield SFX.

## Provenance

- Source root: `/src`, mounted from the canonical working tree
  `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- Source manifest: `4ff6260cf89396c0d4a5c96c889b89558cab599e33c4b26976921ce629749efc`
- Source-manifest entries: `1697`
- Release build: `/tmp/clamav-release-current-20260913`
- ASan/UBSan build: `/tmp/clamav-asan-current-20260912`
- Runner: existing disposable `rust:1.97-bookworm` container,
  `arm64` Linux; no software was installed for this run

## Results

The following `cl_suite` cases were run with `CK_RUN_CASE` in both builds:

| Case | Release | ASan/UBSan |
| --- | ---: | ---: |
| `arj_compressed` | 2/2 | 2/2 |
| `arj_map` | 8/8 | 8/8 |
| `binhex_map` | 15/15 | 15/15 |
| `mydoom_map` | 5/5 | 5/5 |
| `bz_map` | 5/5 | 5/5 |
| `bz_core` | 10/10 | 10/10 |
| `cabsfx` | 3/3 | 3/3 |
| `sis` | 1/1 | 1/1 |
| `sis_structure` | 3/3 | 3/3 |
| `sis_member` | 1/1 | 1/1 |
| `ishield_sfx` | 1/1 | 1/1 |
| **Total** | **54/54** | **54/54** |

Both runners exited successfully with zero failures and zero errors. The
ASan/UBSan output contained no sanitizer, leak, undefined-behavior, or
runtime-error diagnostics.

## Qualification boundary

This is current-source ARM64 development evidence only. It does not replace
the roadmap's complete parser corpus, exact/materialized 32-GiB fixtures,
certified Linux x86-64 Release and sanitizer runs, production CVD/service
evidence, resource and fanotify evidence, Sonic1 evidence, or final release
qualification. No capability status was promoted.
