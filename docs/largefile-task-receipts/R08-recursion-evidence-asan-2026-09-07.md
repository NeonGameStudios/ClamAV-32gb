# Task receipt: R08 recursion-state and evidence ownership sanitizer closure

Task ID / parent milestone: `R08`.

Exact capability kind:ids:

- `library:magic-scan-context-admission`
- `library:alert-callback-dismissal-failure`
- `library:indicator-evidence-add-failure`

This receipt records ARM64 development verification only. It does not promote
any capability or replace the certified Linux x86-64 qualification run.

## Source and build identity

- Canonical checkout: `/Volumes/512gbNVME/github-external/ClamAV-32gb`.
- Branch: `largefile-roadmap-qualification`.
- Base HEAD: `ff8905891b2b58a66c71859ab2c807cc4dee2dec`.
- Both tested builds embedded the pre-receipt dirty-source manifest SHA-256
  `dfa3f2edad749c7979c7dd1f934fe2a243d8f4ede0462e7b37453de3c64b6ef8`.
- The rebuilt ARM64 static C AddressSanitizer `check_clamav` SHA-256 is
  `d1d4b3c29cfeb5195adef1f8b14a954c3fd354093649e730cff3dfa4c1d3494f`.
- The rebuilt ARM64 normal static, UnRAR-enabled `check_clamav` SHA-256 is
  `d99b8ec9f2f6f45b68af1cdbda87f065b5d0eadec8fcb6e5c2d886ad9ce3ac10`.
- The existing dirty working tree was preserved. No reset, clean, commit,
  push, deployment, GitHub workflow action, or host package installation was
  performed.

## Observed failures and root causes

The first complete shared-process C AddressSanitizer run aborted in
`test_cli_magic_scan_missing_recursion_state_is_fail_visible`. The public
entrypoint correctly rejected a one-past recursion level, but its failure path
called `cli_mark_scan_incomplete()` and then `emax_reached()`. That helper
indexed the same invalid level while attempting to taint parent maps. ASan
reported an eight-byte read past the one-element `cli_scan_layer_t` stack at
`emax_reached()`.

After repairing that access, the focused `cl_api` case completed 500/500 but
LeakSanitizer found two ownership gaps: `cli_virus_found_cb()` retained the
Rust `FFIError` returned by failed evidence removal, and the direct-call script
normalization test retained its merged root `Evidence` object.

The next complete run completed 2,788/2,788 assertions but exited for leaks:
9 direct-leak reports represented 13 retained root `Evidence` allocations in
five direct parser tests, with 6,556 bytes in 65 total allocations. Those tests
called parser internals directly and therefore bypassed the public scan
cleanup that normally owns root evidence. The five affected tests were:

- `test_onenote_corpus_detects_embedded_mz`
- `test_utf16_html_uses_bounded_decoding`
- `test_encoded_text_script_normalization_is_complete`
- `test_mscab_corpus_detects_embedded_mz`
- `test_xar_subdocument_serializes_inner_close`

## Changes

- `emax_reached()` now rejects a missing or zero-capacity stack, clamps an
  invalid recursion level to the last real entry, and walks toward zero with
  unsigned underflow-safe control. It still marks the current fmap and every
  real parent non-cacheable.
- The recursion-state regression now exercises both one-past and
  `UINT32_MAX` levels with distinct current and parent maps, requiring both to
  become non-cacheable. This covers both the former out-of-bounds access and
  the former signed-narrowing skip.
- `cli_virus_found_cb()` formats a nullable evidence-removal diagnostic and
  frees the returned Rust `FFIError`. `append_virus()` likewise frees a failed
  evidence-add error object at its common exit.
- The Linux static test shape wraps `ffierror_free()`, and the existing alert
  callback regression requires exactly one release.
- A shared test-only layer-evidence teardown helper releases all non-null
  evidence owned by direct-call recursion layers. The five affected parser
  tests invoke it before closing or reusing their fmaps.
- Source guards pin the recursion clamp, extreme-level regression, both FFI
  error releases, linker wrapper, release-count assertion, and direct-call
  evidence teardown helper.

## Development verification

- Focused post-fix `cl_api` C AddressSanitizer case: 500 checks, zero
  failures, zero errors; exit 0 with no sanitizer report.
- Complete ARM64 static C AddressSanitizer suite with
  `detect_leaks=1`, `halt_on_error=1`, `T=120`, and `CK_FORK=no`: 2,788
  checks, zero failures, zero errors; exit 0 with no AddressSanitizer or
  LeakSanitizer report.
- The sanitizer configuration has `ENABLE_UNRAR=OFF`; its 2,788 count is not
  presented as the UnRAR test shape. Rust dependencies were not sanitizer
  instrumented, so this is C sanitizer evidence only.
- Complete ARM64 normal static suite with `ENABLE_UNRAR=ON`, `T=120`, and
  `CK_FORK=no`: 2,834 checks, zero failures, zero errors; exit 0. This also
  crossed the earlier allocator-history bytecode crash points.
- `sh tools/largefile_source_guards.sh`: exit 0 after inventory and snapshot
  regeneration.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md`: exit 0 after regeneration.
- `git diff --check`: exit 0.
- `sh tools/largefile_release_readiness.sh --status`: expected exit 1 with
  597 total capabilities, 0 qualified, 143 bounded, 440 pending, 14
  allowlisted unsupported, and 583 blockers. Release readiness remains
  blocked.

## Retained diagnostics

The retained logs are outside the source tree in
`/private/tmp/clamav-recursion-asan.ySQYuK`.

- Baseline stack-overflow test log SHA-256:
  `eb19b9928b4a5187618a10e2ef38c47d5bfb29ee8bfbd8f2c730ceac75f711c5`.
- Baseline stack-overflow stderr SHA-256:
  `c3e035de13d2f95914435465abe1364218c48731eeadc0f5e4d3d7c6c97b05c3`.
- Focused two-leak report SHA-256:
  `9eb3ac331810968b0724c60bada438fbd8120c9314df4bcb98b40ebb20fd8e09`.
- Complete five-test leak report SHA-256:
  `5d69b9599a541c215ecbef8ef36aa4a339cdf363459f5fd1fdcfb7e7e0c37e9c`.
- Clean focused `cl_api` test/stderr SHA-256:
  `da0e54332c42e295ddbeb0fc4f720c8c4126566acf75be877a9053982554e1dc` /
  `91672c32a2a682bfb407775bc7942d478e5160887723cbf300c32e2b9f36c840`.
- Clean complete sanitizer test/stderr SHA-256:
  `3b199efe21ba6f500488eb4574fa1311fcdec6de42543628a70ebdce691db907` /
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- Clean complete sanitizer build log SHA-256:
  `2f821c2e95ff1f6f6df62c9c3ad84589a13abe758b24281fafc410672a6dd659`.
- Clean complete normal test/stderr SHA-256:
  `c087ce52102b093488a4d375cc29da2d43bea70275234220d061d6754428da54` /
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- Clean complete normal build log SHA-256:
  `6f43fbb46de376275aa1ac6ceb97eeea79c8752e098beb7f877da86ade78dbea`.

## Limits and next action

No certified Linux x86-64 sanitizer or Release run, Rust sanitizer run,
production-CVD/service run, materialized 32-GiB case, Sonic execution, or R04
qualification record was produced. Retain these regressions for the authorized
x86-64 runner and keep all three capabilities at their existing non-qualified
status.

State: `development-verified`; release qualification remains pending.
