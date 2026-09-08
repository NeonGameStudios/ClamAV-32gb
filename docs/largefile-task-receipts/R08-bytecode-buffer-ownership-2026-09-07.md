# Task receipt: R08 bytecode buffer ownership initialization

Task ID / parent milestone: `R08`, with supporting coverage for `R07`

Exact capability kind:id: `library:bytecode-api-constructor-atomicity`.
The matching focused test family is `bytecode:map_read`. This receipt records
ARM64 development verification only and does not promote the capability.

## Source and build identity

- Canonical checkout: `/Volumes/512gbNVME/github-external/ClamAV-32gb`.
- Branch: `largefile-roadmap-qualification`.
- Base HEAD: `ff8905891b2b58a66c71859ab2c807cc4dee2dec`.
- The pre-receipt dirty-source manifest SHA-256 was
  `bb9564140db3993647c423593864f8118da33a667c3fd3725d31001b2eaded5c`.
- The existing dirty working tree was preserved; no reset, clean, commit, or
  push was performed.
- The stale pre-fix ARM64 `check_clamav` SHA-256 was
  `e161f7df65fc64b840b5d689d91f4027e9b6fa0cd5035d62ca5e035b98ad9234`.
- The rebuilt post-fix ARM64 static `check_clamav` SHA-256 is
  `b26b01611b5e89defa0d8882dfd52ecf1e769454fa34ca89457c759580c9305e`.
- The post-fix ARM64 C AddressSanitizer `check_clamav` SHA-256 is
  `540d97afeee2909d66477a153b9e6317cf358d6c9b1643d80534b717f15f7e09`.

## Observed failure and root cause

The complete current-source C suite initially exited with `SIGSEGV` after it
entered the bytecode tests. A process-isolated diagnostic run completed 2,831
checks with ten errors: eight ARM-container timeout errors and two bytecode
`SIGSEGV` errors in
`test_bytecode_v2_uses_64bit_file_coordinates` and
`test_bytecode_bzip2_decoder_finalization_failure_is_fail_visible`.
The bytecode suite and its `map_read` case passed in isolation without
allocator perturbation, demonstrating an allocator-history dependency.

Running the stale binary with `MALLOC_PERTURB_=165`, process isolation, and
the `bytecode:map_read` selection reproduced the defect deterministically:
21 checks, zero assertion failures, and one `SIGSEGV` after
`test_bytecode_jsnorm_limit_failure_releases_input`.

All three bytecode buffer constructors grew `ctx->buffers` with `realloc()`
but initialized only their legacy data, size, and cursor fields. The newer
`map_read_fmap`, `map_read_offset`, `map_read_length`, and `map_read_locked`
fields could therefore retain heap bytes. A later read or cleanup could treat
those bytes as owned fmap state and dereference or release a bogus pointer.

## Changes

- `cli_bcapi_buffer_pipe_new()`,
  `cli_bcapi_buffer_pipe_new_fromfile()`, and
  `cli_bcapi_buffer_pipe_new_fromfile64()` now publish the reallocated table,
  zero the complete new slot, initialize its intended state, and only then
  publish the increased buffer count.
- `test_bytecode_buffer_pipe_initializes_map_ownership` reserves and fills an
  unpublished slot with `0xa5`, invokes each constructor in a three-iteration
  loop, verifies every ownership field is clear, verifies an existing live
  map lock survives table growth, exercises the resulting buffer, and checks
  cleanup.
- Source guards pin the regression, deterministic prefill, constructor
  initialization, and capability description.
- The capability manifest remains `pending`; its description now records the
  fixed stale-ownership boundary and the development evidence.

## Development verification

- Post-fix bytecode suite, shared process: 87 checks, zero failures, zero
  errors; exit 0.
- Post-fix bytecode suite with process isolation and
  `MALLOC_PERTURB_=165`: 87 checks, zero failures, zero errors; exit 0.
- Post-fix complete shared-process C suite with the signing-certificate input
  configured: 2,834 checks, zero failures, zero errors; exit 0. This crossed
  both former crash points.
- ARM64 static C AddressSanitizer bytecode suite with leak detection and
  fail-fast sanitizer behavior: 87 checks, zero failures, zero errors; exit 0
  with no AddressSanitizer or LeakSanitizer report. Rust dependencies were not
  sanitizer-instrumented, so this is C sanitizer development evidence only.
- The first sanitizer invocation completed 87 checks with two ordinary fixture
  failures because the focused binary target had not materialized
  `clam.exe`; it exited 1 without a sanitizer finding. Building the declared
  `tgt_clamav_hdb_scanfiles_clam.exe` target produced the fixture, after which
  the unchanged sanitizer binary passed as reported above.
- `sh tools/largefile_source_guards.sh`: exit 0, including the synchronized
  generated inventory, 597-row capability manifest, readiness controls,
  snapshot tests, acceptance producers/verifiers, fanotify and PCRE evidence
  controls, and the empty authoritative record-set check.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md`: exit 0 after regeneration.
- `git diff --check`: exit 0.
- `sh tools/largefile_release_readiness.sh --status`: expected exit 1 with 597
  total capabilities, 0 qualified, 143 bounded, 440 pending, 14 allowlisted
  unsupported, and 583 blockers. Release readiness remains blocked.

Retained diagnostic logs outside the source tree:

- Full-run test log SHA-256:
  `9e74c1bfc88064563c6ed5ac006a2c4a364439559554e2ad7ac0d4e25987a26c`.
- Full-run stderr SHA-256:
  `e753af27edf2a18b5ce37acab0c0486c09eaf29d90e000b8bdab2efa4513bc3d`.
- Perturbed focused test log SHA-256:
  `aa4efa003c047c264400f163a1f73100223c8c41436c7a201b2190f1adad2274`.
- Perturbed focused stderr SHA-256:
  `e57498760670b92b08b321bc7dd5c1157f2ad7894a805053069c19030c1d17b6`.
- C AddressSanitizer bytecode test log SHA-256:
  `0e5dd632487d777595bbf338c171bb7bbd42a12ddda8f3416e10550011a70a5e`.
- C AddressSanitizer bytecode stderr SHA-256:
  `aba8a0f224e7247fd41e5591bfaa8e8f6832c8478b9112dad0bbe7244a0e734e`.

## Limits and next action

No certified Linux x86-64 Release or sanitizer build, Rust sanitizer run,
independent format-8 bytecode artifact, production-CVD/service run,
materialized 32-GiB case, or R04 qualification record was produced. The
authorized x86-64 runner and compatible external format-8 compiler/artifact
remain external prerequisites. After the local integrity controls finish,
retain this regression on the certified runner and bind the applicable
bytecode cases through R04.

State: `development-verified`; release qualification remains pending.
