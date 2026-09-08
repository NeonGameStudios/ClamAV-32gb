# Task receipt: R04 capability-specific case schema

Task ID / parent milestone: `R04` / `R00`

Exact capability kind:id list: all 597 capability rows are covered by the
generated `docs/largefile-capability-case-map.tsv`; no row is promoted to
qualified by this schema slice.

Starting commit and working-tree/source manifest identity: current dirty
`largefile-roadmap-qualification` worktree; existing changes were preserved.

Prerequisites verified: the 597-row capability manifest passed its validator;
the roadmap requirement that parser-only coverage is insufficient was applied
to library, matcher, feature, ingress, parser, and deliberate-unsupported rows.
The certified Linux x86-64 runner remains unavailable.

Owned files and excluded shared files: `tools/largefile_acceptance_cases.py`,
its tests, `docs/largefile-capability-case-map.tsv`,
`docs/largefile-acceptance-cases.tsv`, this receipt, and the source-guard hook.
Runtime producers and readiness promotion logic remain coordinator-owned.

Observed failing case and expected behavior: before this slice there was no
machine-readable capability-to-required-case mapping or case-record schema, so
a generic proof could not be required to contain the actual parser/matcher case
it claimed. Expected behavior is exact capability/case binding with independent
source/build/config/fixture/oracle/database identities, exact outcomes and
alerts, counters, sanitizer/resource phase fields, health, cleanup, and retained
artifacts.

Changes made: added deterministic routing for all 597 capabilities; added a
reviewed map with capability-specific cases for parsers, matchers, features,
ingress, library APIs, and unsupported rows; added fail-closed validation for
case records; added negative tests for missing capabilities, unrequired cases,
contradictory outcomes, and missing exact alert offsets. The service
qualification producer and runtime boundary producer now translate only
explicitly mapped workload labels into capability records, preserve unmapped
workloads as unmapped, and emit records before their checksum manifests are
finalized. The service/runtime evidence checkers and authoritative readiness
gate validate retained artifact hashes and service-fixture identity against
the records. The repository records file is intentionally empty and
schema-valid: empty records cannot qualify anything.

Commands and exits:

- `python3 -B tools/largefile_acceptance_cases_test.py` — exit 0, 4 tests passed.
- `python3 -B tools/largefile_acceptance_case_producer_test.py` — exit 0, 2 tests passed, including tampered-artifact rejection.
- `python3 -B tools/largefile_runtime_acceptance_case_producer_test.py` — exit 0, 1 test passed, binding both runtime detection-edge records.
- `python3 -B tools/largefile_acceptance_cases.py --check-map` — exit 0, 597 capabilities.
- `python3 -B tools/largefile_acceptance_cases.py --check-records` — exit 0, 0 records; qualification remains incomplete.
- `sh tools/largefile_service_evidence_check_test.sh` — exit 0, including acceptance-record integration.
- `sh tools/largefile_runtime_evidence_check_test.sh` — exit 0, including acceptance-record integration.
- `git diff --check` — exit 0.
- `sh tools/largefile_source_guards.sh` — exit 0.

Development tests passed: schema and mapping tests pass. No full-size case record,
sanitizer evidence, fanotify evidence, or capability qualification was produced.

Full-size/certified evidence produced, or explicitly not run: not run; runner and
build prerequisites are unavailable.

Remaining failures / next slice: extend the binding to clean/limit, daemon,
library, and full-size producers, then populate the complete case matrix from
R03/R11/R12 evidence. Runtime currently binds only clamscan file/stdin
detection edges; clean, limit, daemon, library, parser, matcher, feature,
milter, and fanotify cases remain absent. Service/runtime evidence is still
not qualification evidence on this macOS/ARM64 checkout, and the release gate
remains blocked.

State: `development-verified`
