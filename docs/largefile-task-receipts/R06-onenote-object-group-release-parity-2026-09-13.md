# R06 OneNote object-group spool Release parity — 2026-09-13

Task ID / parent milestone: `R06` / `R03`.

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE` and
`feature:onenote-modern-over-256m`; no capability status change.

## Scope

Rebuild the current-source ARM64 Release `check_clamav` target after the
object-group payload spooling change, then rerun the production-linked
reader-backed OneNote cases.

## Provenance

- checkout: `/Volumes/512gbNVME/github-external/ClamAV-32gb`, branch
  `largefile-roadmap-qualification`; intentionally dirty working tree
  preserved;
- source manifest: 1,697 entries, SHA-256
  `3c8f5a0ecdb04aba70531067e35628ae95edad6c723bd9f08624f109ea41edd6`;
- build directory: `/tmp/clamav-release-current-20260913` in the existing
  disposable ARM64 Docker container;
- `reader.rs` SHA-256: `a851ed4739d087b481c8827af10bdf729e506278c637d45327e6f05c884b1ad6`;
- fresh `unit_tests/check_clamav` SHA-256:
  `c24a412a68502e1dfc6686bce9707e80918acfbb889888111b601efbb47f43d3`;
- `CMakeCache.txt` SHA-256:
  `af2fe69b889f05d0ab5b6b87d1bb742873825371d8226e6a414275a74c08d959`;
- configuration: Release, `ENABLE_APP=ON`, `ENABLE_MILTER=ON`, `ENABLE_TESTS=ON`,
  `ENABLE_UNRAR=ON`, large-file defaults and qualification test off.

## Verification

- `cmake --build /tmp/clamav-release-current-20260913 --target check_clamav -j2`
  — exit 0; Rust and C consumer target rebuilt and linked.
- `CK_FORK=no CK_RUN_SUITE=cl_suite CK_RUN_CASE=rust_onenote T=1200
  ./check_clamav` — exit 0; 4/4 checks passed with zero failures and errors.
- `ctest --test-dir /tmp/clamav-release-current-20260913
  --output-on-failure` — exit 0; 28/28 tests passed in 274.99 seconds.
- The focused group includes the current-source reader-backed input above the
  former 256-MiB logical cap and the corpus attachment handoff with temporary
  reservation cleanup assertions.

## Qualification boundary

This is ARM64 development Release parity only. It does not prove the exact
32-GiB materialized edge, certified Linux x86-64 execution, production CVD or
service behavior, full late-offset OneNote coverage, resource/fanotify
evidence, or final release qualification. No capability was promoted.

State: `development-verified; qualification-open`.
