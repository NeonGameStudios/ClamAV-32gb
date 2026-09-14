# Task receipt: R13 PCRE runtime phase markers — 2026-09-12

## Scope

The PCRE evidence verifier already required process-tree samples and a
subject-release transition, but the scanner had no runtime event identifying
where the full subject was handed to PCRE, released, or followed by parser
dispatch. This slice adds those debug-only boundaries and makes the verifier
check the retained process log rather than trusting transition booleans alone.

## Changes

- `libclamav/matcher.c` now emits `before-pcre`, `pcre`, and
  `post-pcre-before-deep-parse` events around the full-map PCRE subject and
  after `fmap_release_unlocked()`.
- `libclamav/scanners.c` emits the `deep-parse` dispatch event at the actual
  parser phase boundary.
- `tools/largefile_pcre_phase_evidence.py` now requires one retained
  process-log artifact containing all four ordered runtime markers and an
  explicit released-subject field on the release and parser events.
- The PCRE verifier regression grew from 8 to 10 cases, including missing and
  out-of-order runtime markers. The generated source inventory was refreshed.

## Verification

All compiled checks used the existing
`clamav-current-rust-build-20260911` Linux ARM64 development container and
the current source mounted at `/src`:

- CMake reconfiguration completed; no software was installed. The existing
  container reports its usual missing optional `pytest` package, which was not
  needed for these checks.
- `cmake --build /tmp/clamav-release-current-20260912 --target clamscan -j2`
  completed and rebuilt `libclamav/matcher.c` and `libclamav/scanners.c`.
- `python3 -B tools/largefile_pcre_phase_evidence_test.py` passed 10/10.
- The focused CTest slice passed 5/5:
  `largefile_source_guards`, `largefile_runtime_evidence_check`,
  `largefile_service_evidence_check`, `largefile_acceptance_case_schema`,
  and `largefile_procfs_tree_rss`. Retained log SHA-256:
  `974b90d0bc33985990649a5d3f32d8dea8806f96b5bdfa1ad6d2775aedc08c6e`.
- A disposable custom PCRE signature scan returned the expected detection
  exit code 1 and emitted all three matcher markers. Its retained log SHA-256
  is `cca156a131ccbefb921184fc10b9db0614126eb37780596d8a7088f49892c99a`.
  The exact hash is intentionally not used as qualification evidence here;
  the small custom/test-CVD database did not provide the production
  raw-before-parser ordering, so its `deep-parse` marker precedes PCRE and
  the independent verifier must reject that run.
- Current source manifest SHA-256:
  `ae5a9f964fcc2ec91e3f613ca63030e0aeb3d0d3c43cd3bd8dfb64fa7b4a32f1`.
- Tracked inventory: 44,674 lines, SHA-256
  `c38bf34d1f45d55640bed835724b322e162c914d745160f9e3d0833f3dc3aab4`.
- `git diff --check` exited 0; its retained output contains only the
  repository's existing CRLF normalization warnings.

## Qualification boundary

This is runtime instrumentation and verifier development evidence only. It
does not claim the 32-GiB materialized full-subject case, Linux x86-64,
40-GiB PCRE or <12-GiB post-PCRE RSS, PSS/swap/page-fault evidence,
production CVDs, sanitizer parity, Sonic1, or release readiness. A future
qualification runner must retain a complete marker sequence in the correct
production ordering and independently sample the process tree at each phase.
