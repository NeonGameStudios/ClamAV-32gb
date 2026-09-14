# Task receipt: R06 OneNote reader at the exact 32-GiB logical boundary — 2026-09-13

Task ID / parent milestone: `R06` / `R03`.

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE`.

## Scope

Strengthen the production-linked reader-backed OneNote regressions so they
exercise the exact supported logical input boundary, `34,359,738,368` bytes,
while retaining a physically small fixture served through bounded reads. This
is development reader/scanner coverage, not a substitute for the roadmap's
fully materialized 32-GiB qualification case.

## Change

The two existing `unit_tests/check_clamav.c` OneNote reader tests now advertise
`CLI_MAX_LARGE_FILESIZE` instead of only `256 MiB + 1`:

- the clean modern section path crosses the former whole-input cap at the
  exact 32-GiB logical boundary;
- the attachment-bearing path reaches the exact boundary and proves nested
  `OneNote.Reader.MZ` detection, callback termination, cache state, and
  temporary-byte release.

The `cl_fmap_open_handle()` callback continues to expose only the small real
fixture and synthesizes zero-filled reads for the logical tail. No giant
buffer, mmap, or sparse qualification artifact is used by these regressions.

## Provenance

- Source root: `/src`, mounted from the canonical working tree.
- Branch: `largefile-roadmap-qualification`.
- Working tree: intentionally dirty; unrelated existing changes preserved.
- Current source-manifest SHA-256:
  `ea89582cd812e7147eb7c5ac06f4c98e54c6103bbc801384dc0c8fb08eb0cbd2`.
- Release `check_clamav` SHA-256:
  `aabb86fc502aeb05a2585705963f1429cca9ed69acc32cbe4288b3baae8ba85b`.
- ASan/UBSan `check_clamav` SHA-256:
  `328473ac355d777b1f294d25f5be297600e8637a44edb3646fae30ca013081cf`.
- Release CMakeCache SHA-256:
  `af2fe69b889f05d0ab5b6b87d1bb742873825371d8226e6a414275a74c08d959`.
- ASan/UBSan CMakeCache SHA-256:
  `342f477d96232ca059ff9cee3bfe052fcfa584e216ee4b229fb83fc15dd43e25`.
- Runner: existing disposable `rust:1.97-bookworm` ARM64 Linux container.

## Verification

- Incremental Release rebuild of `check_clamav`: passed.
- Incremental ASan/UBSan rebuild of `check_clamav`: passed.
- `CK_RUN_CASE=rust_onenote ctest --test-dir /tmp/clamav-release-current-20260913 -R '^libclamav$' --output-on-failure`: passed, 1/1 in 29.55s.
- `CK_RUN_CASE=rust_onenote ctest --test-dir /tmp/clamav-asan-current-20260912 -R '^libclamav$' --output-on-failure`: passed, 1/1 in 36.33s.
- No ASan, UBSan, leak, or runtime-error diagnostics were emitted.

## Qualification boundary

This is current-source ARM64 development evidence. It does not establish
certified Linux x86-64 execution, full materialized 32-GiB input, production
CVD/service behavior, resource/fanotify evidence, Sonic1 execution,
independent format-8 bytecode evidence, or final release qualification. No
capability status was promoted. No software was installed, no usage reset was
used, and no commit, push, or GitHub workflow action was performed.

State: `development-verified`; exact 32-GiB logical reader boundary passed;
materialized and certified R06 completion remain pending.
