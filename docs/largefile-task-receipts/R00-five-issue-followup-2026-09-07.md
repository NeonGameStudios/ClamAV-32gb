# Task receipt: five-issue roadmap follow-up

Task ID / parent milestone: `R00` follow-up across `R03`, `R04`, `R06`,
`R09`, and `R10`

Scope: continue the five issues identified by the roadmap review using only
the canonical local checkout and existing disposable Docker artifacts. This
receipt records the current disposition; it does not promote any capability
to release-qualified.

Canonical source and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- working tree intentionally remains dirty and was not reset or cleaned
- pre-receipt source-manifest SHA-256:
  `7542de5ed0eb41d23d7253585be8822b39523e4e7354b9d1d26bf453387febb7`

## Issue disposition

1. **Certified qualification runner.** No Linux x86-64 runner was available
   locally, and no remote/MCP execution was used. The current ARM64 Docker
   build remains development evidence only. This issue is blocked by the
   external runner prerequisite.

2. **Safe refusal versus required implementation.** R09's five focused
   parser cases are fail-visible and raw matching remains available where
   required. Modern OneNote remains explicitly bounded at the dependency's
   whole-input API boundary; the pinned parser exposes only
   `parse_section_buffer(&[u8])` for the needed path, so no unsafe cap increase
   or whole-file adapter was added. R06 remains blocked by the dependency API.

3. **Capability-specific acceptance evidence.** The reviewed capability map,
   case suffix contracts, producer, and evidence-root hash checks are present
   and were rerun below. Standalone parser/matcher records now must retain an
   artifact whose digest is the scanned fixture digest; service records may
   instead bind that digest through the independently captured service-input
   identity. The current empty authoritative records state still blocks
   qualification; focused development records do not qualify unrelated
   capabilities.

4. **Service fixture binding.** The exact 32-GiB edge-size rule, allocation
   and `SEEK_HOLE` checks, mutation identity checks, and before/after evidence
   comparison are present. Their focused controls pass, but no full-size
   materialized service run was attempted without the certified runner.

5. **Source/status provenance.** Work was performed from the canonical Git
   checkout. The generated short snapshot is fresh, while historical status
   documents remain historical and are not used as current evidence.

## Current development verification

The refreshed disposable ARM64 binaries were built from the current source
candidate. Their retained hashes are:

- `clamd`: `695f651a2fa6cf6aaedff0c7776e92c41de658ebfc7453663ffca40bc150410f`
- `clamdscan`: `52d9e26eb0d1de76b610dc9971695996c99680acbcfb54784ccd16a4405355f3`
- `check_clamav`: `e161f7df65fc64b840b5d689d91f4027e9b6fa0cd5035d62ca5e035b98ad9234`
- `check_clamfi_quota`: `d8cb421d8aef4835070ccf6c488a0eaca6c2e6d0ace58a046516146e8279b979`

Commands and actual results:

- `CK_FORK=no CK_RUN_SUITE=cl_suite CK_RUN_CASE=required_unsupported ./check_clamav` in the disposable ARM64 container: **5 checks, 0 failures, 0 errors; exit 0**.
- `./check_clamfi_quota` in the disposable ARM64 container: **exit 0**.
- `python3 -B tools/largefile_acceptance_cases_test.py`: **8 tests passed**, including rejection of forged standalone and unretained service fixture identity bindings.
- `python3 -B tools/largefile_acceptance_case_producer_test.py`: **3 tests passed**.
- `python3 -B tools/largefile_runtime_acceptance_case_producer_test.py`: **4 tests passed** after retaining each runtime producer's scanned input artifact.
- `python3 -B tools/largefile_service_workload_check_test.py`: **19 passed, 2 Linux-only filesystem tests skipped**.
- `python3 -B tools/largefile_status_snapshot_test.py`: **12 tests passed**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md`: **exit 0**.
- `git diff --check`: **exit 0**.
- `sh tools/largefile_source_guards.sh`: **exit 0**, including the complete 597-row inventory/readiness and acceptance-control suite.
- `sh tools/largefile_release_readiness.sh --status`: **exit 1 as expected** with `597` total, `0` qualified, `143` bounded, `440` pending, `14` allowlisted unsupported, and `583` blockers.

Follow-on R04 evidence-retention correction:

- `tools/largefile_acceptance_cases.py` now requires a service-backed record
  to retain `provenance/service-inputs-before.json` in its artifact list before
  using that sidecar to bind the fixture hash. The sidecar must also carry the
  versioned object schema. This prevents an unretained identity file from
  influencing a capability record.
- `tools/largefile_acceptance_cases_test.py` adds a regression proving that an
  omitted service-input identity file is rejected and that the same record
  passes once the identity file is retained.
- `sh tools/largefile_source_guards.sh` passed after the correction. This is a
  verifier-integrity improvement only; it does not create runtime records or
  promote any capability.

## Explicitly unrun or blocked

- The fragmented milter integration harness was not converted into evidence:
  the cached runtime has no `libmilter.so.1.0.1`, so the milter process cannot
  start without installing a missing dependency. The milter source was
  inspected and no source defect was demonstrated in this slice.
- No current-source Linux x86-64 Release/sanitizer build, production-CVD
  workload, full-size materialized edge, privileged fanotify run, or final
  canary was claimed.
- No software was installed, no remote host was contacted, no usage reset was
  used, no GitHub workflow was changed or triggered, and no commit or push was
  performed.

Remaining action: obtain the authorized x86-64 runner and a reviewed
reader-backed modern OneNote API or implementation boundary; then bind the
fresh certified runs to the existing R04 case map and continue R11–R15.

State: `development-verified` for the local controls; certified release
qualification remains blocked.
