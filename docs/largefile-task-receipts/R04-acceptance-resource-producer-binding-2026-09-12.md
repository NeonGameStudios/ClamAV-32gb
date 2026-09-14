# Task receipt: R04 acceptance resource producer binding — 2026-09-12

Task ID / parent milestone: `R04` / R14

## Gap

The service acceptance producer translated genuine service workload reports
into R04 records, but it had no way to bind the independently captured
per-case resource sidecar. Resource validation existed at the readiness gate,
but the producer pipeline could silently emit unbound development records even
when a sidecar was available.

## Changes

- `tools/largefile_acceptance_case_producer.py` now accepts
  `--resource-sidecar` and `--require-resource-sidecar`.
- `tools/largefile_runtime_acceptance_case_producer.py` exposes the same
  binding options for exact-edge runtime records.
- When requested, the producer calls the strict sidecar binder after writing
  the records. The binder verifies exact case coverage, source/build/config
  hashes, certified platform, procfs sampler identity, memory relationships,
  zero swap/OOM, and retained sidecar hash/path bindings.
- The service qualification runner now captures the sidecar per mapped
  workload while the daemon and active client are live, retaining separate
  peaks for each case before finalizing the build-identity hashes.
- The default development behavior remains unchanged when no sidecar option
  is supplied; authoritative readiness still requires the sidecar.
- Added a producer integration regression and a direct CTest registration.

## Verification

- Acceptance producer tests — 9/9 passed, including the sidecar-binding case.
- Runtime acceptance producer tests — 7/7 passed, including six-case sidecar
  coverage.
- Existing resource-contract and capture tests — 9/9 passed.
- Current-source focused CTest passed 6/6 after reconfiguration:
  source guards, acceptance schema, resource schema, resource-capture
  producer, acceptance-case producer, and runtime acceptance-case producer.
- The full source-guard sweep passed after the service-runner integration.
- Current source manifest: 1,693 lines,
  SHA-256 `f2db32e87842c846da4d8064bc546930f7d7d9787a2ec676db12e07b6e9d0faf`.
- No capability was promoted and no production or certified runner evidence
  was created.

## Boundary

This connects the sidecar contract to record generation but does not create
the missing certified Linux x86-64 production canary. R07 still lacks the
external format-8 compiler/artifact, and R11–R15 evidence remains open. No
dependency was installed, no usage reset was used, and no commit, push, or
GitHub CMake workflow action was performed.

State: `development-verified`
