# Task receipt: R14 per-case resource contract — 2026-09-12

Task ID / parent milestone: `R14` / R13

Exact capability kind:id list: the shared R04 acceptance-case record contract;
no capability row was promoted to qualified.

## Gap

Acceptance records carried declared RSS and temporary-space budgets, but did
not carry an independently bound measurement for the individual case. A
daemon-wide peak or a copied budget label could therefore be mistaken for the
per-parser R14 record required by `PLAN.md`.

## Changes

- Added `tools/largefile_acceptance_resources.py` with the strict
  `provenance/acceptance-case-resources.tsv` schema and
  `tools/largefile_acceptance_resource_capture.py` as its live producer.
- The sidecar binds each case to its source manifest, build, configuration,
  platform, and approved Linux procfs process-tree sampler, and records sample
  count, RSS/PSS/VAS, swap, page faults, read/write I/O, cancelled writes,
  temporary peak, OOM counters/cgroup identity, and PCRE/post-PCRE peaks.
- The producer samples a live command tree through the existing procfs metric
  and cgroup-v2 OOM samplers, tracks recursive temporary-tree peaks, and
  supports an ordered `pcre-start`/`post-pcre`/`complete` phase protocol.
  It validates before writing, preserves the wrapped command's exit result,
  and rejects an uncertified platform without emitting a row.
- The verifier rejects non-x86-64 evidence, missing samples, nonzero swap,
  invalid PSS/VAS relationships, budget excesses, non-PCRE phase claims, and
  missing capability cases.
- `--bind` adds the sidecar hash and retained artifact path to every case
  record. Authoritative release readiness now requires the bound sidecar for
  every capability it attempts to qualify; development evidence remains
  allowed to omit it.
- The service qualification runner now produces one sidecar row per mapped
  service workload from live daemon-plus-client process-tree samples, then
  binds the finalized sidecar to the generated acceptance records.
- Registered both regressions in CTest and the source guards.

## Verification

- `python3 tools/largefile_acceptance_resources_test.py` — 5/5 passed.
- `python3 tools/largefile_acceptance_resource_capture_test.py` — 3/3 passed.
- Combined resource-contract and producer regression tests — 9/9 passed.
- Full host tool suite — 156 passed, 2 expected Linux-only skips.
- Snapshot freshness, acceptance-map, shell syntax, and `git diff --check` —
  passed.
- Reused current-source ARM64 container reconfiguration — passed.
- Current-source focused CTest — 4/4 passed:
  `largefile_source_guards`, `largefile_acceptance_case_schema`,
  `largefile_acceptance_case_resources`, and
  `largefile_acceptance_resource_capture`.
- Reconfigured current-source focused CTest after service-runner integration —
  6/6 passed, including both acceptance producers.
- A real Linux process capture in the existing ARM64 container sampled the
  process tree but failed closed at the certified-platform validation boundary;
  a second fresh capture confirmed that no invalid sidecar row is emitted.
- Current source manifest: 1,693 lines,
  SHA-256 `f2db32e87842c846da4d8064bc546930f7d7d9787a2ec676db12e07b6e9d0faf`.

## Boundary

No full-size resource sidecar was produced because the certified Linux x86-64
runner and production canary are still unavailable. This is contract and
development verification only; certified Release/sanitizer, full materialized
parser cases, production CVD/service behavior, Sonic1, real fanotify
permission evidence, and final release readiness remain open. No dependency
was installed, no usage reset was used, and no commit, push, or GitHub CMake
workflow action was performed.

State: `development-verified`
