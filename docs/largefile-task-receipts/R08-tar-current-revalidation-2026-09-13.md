# Task receipt: R08 current-source TAR revalidation — 2026-09-13

Task ID / parent milestone: `R08` / `R03`.

## Scope

Re-run the TAR direct-map, member-output, parser, and corpus slices against
the current source in both retained application build variants. These tests
cover bounded member staging, coordinate advancement, EOF/end-marker
handling, temporary-output cleanup, and fail-visible read/limit behavior.

## Provenance

- Source root: `/src`, mounted from the canonical working tree.
- Branch: `largefile-roadmap-qualification`.
- Working tree: intentionally dirty; existing changes preserved.
- Current source-manifest SHA-256:
  `ea89582cd812e7147eb7c5ac06f4c98e54c6103bbc801384dc0c8fb08eb0cbd2`.
- Release build: `/tmp/clamav-release-current-20260913`.
- ASan/UBSan build: `/tmp/clamav-asan-current-20260912`.
- Runner: existing disposable `rust:1.97-bookworm` ARM64 Linux container.

## Verification

| Build | Case | Result |
| --- | --- | ---: |
| Release | `tar_map` | 1/1 |
| ASan/UBSan | `tar_map` | 1/1 |
| Release | `tar_member` | 1/1 |
| ASan/UBSan | `tar_member` | 1/1 |
| Release | `tar` | 1/1 |
| ASan/UBSan | `tar` | 1/1 |
| Release | `tar_corpus` | 1/1 |
| ASan/UBSan | `tar_corpus` | 1/1 |

All eight focused CTest invocations exited successfully. No ASan, UBSan,
LeakSanitizer, or runtime-error diagnostics were emitted.

## Qualification boundary

This is ARM64 development evidence only. It does not provide the roadmap's
capability-specific acceptance records, full-size/materialized fixtures,
production-CVD/service, certified Linux x86-64, resource/fanotify,
independent format-8, Sonic1, or final release evidence. No capability status
was promoted. No software was installed, no usage reset was used, and no
commit, push, or GitHub workflow action was performed.

State: `development-verified`; current TAR slices passed; parser-family and
release qualification remain pending.
