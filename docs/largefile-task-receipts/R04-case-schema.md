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
case records, including exact TSV row-width validation and strict CSV parsing
so extra, missing, or malformed quoting cannot be silently ignored.
The service and runtime acceptance
producers, status snapshot, and PDF object-stream evidence checker use strict
TSV readers for their input tables; added negative tests for missing
capabilities, unrequired cases, contradictory outcomes, missing exact alert
offsets, empty fields, and malformed row widths. The service qualification
producer and runtime boundary producer now translate only
explicitly mapped workload labels into capability records, preserve unmapped
workloads as unmapped, and emit records before their checksum manifests are
finalized. The service/runtime evidence checkers and authoritative readiness
gate validate retained artifact hashes and service-fixture identity against
the records. The repository records file is intentionally empty and
schema-valid: empty records cannot qualify anything.

Commands and exits:

- `python3 -B tools/largefile_acceptance_cases_test.py` — exit 0, 11 tests passed, including malformed-quoting and symlinked-artifact rejection in the shared TSV reader.
- `python3 -B tools/largefile_status_snapshot_test.py` — exit 0, 13 tests passed.
- `python3 -B tools/largefile_pdf_objstm_evidence_check_test.py` — exit 0, 6 tests passed, including malformed-quoting and symlinked-manifest-path rejection.
- `python3 -B tools/largefile_acceptance_case_producer_test.py` — exit 0, 8 tests passed, including tampered-artifact, traversal-before-read, symlink-before-read, special-kind, unknown-label, and malformed-workload rejection.
- `python3 -B tools/largefile_runtime_acceptance_case_producer_test.py` — exit 0, 6 tests passed, binding runtime detection-edge records, malformed-oracle rejection, and symlinked-path rejection.
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

Follow-on resource-phase binding correction (2026-09-10 UTC):

- Acceptance records no longer satisfy the resource-evidence field with a
  bare label such as `bounded` or `focused`. The validator requires structured
  RSS/temporary budget tokens, or the explicit development-envelope
  max-file/max-temp form; PCRE records additionally require the PCRE and
  post-PCRE phase tokens.
- Added a regression for the rejected bare-label case and updated the focused
  synthetic/service records to use the producer format. Acceptance schema,
  producer, development service, readiness, inventory, and full source-gate
  checks pass. The authoritative records file remains empty; no capability was
  promoted.

Follow-on evidence-path boundary correction (2026-09-08): the shared
acceptance validator, service workload verifier, runtime acceptance producer,
and PDF evidence checker now reject symlink components before resolving
retained paths. The service producer admits report and log paths before
opening either file, rejects unsupported workload kinds and malformed
offset-check fields, rejects unknown workload labels instead of silently
dropping them, and shares the same no-symlink policy. The focused suites
pass: acceptance schema 11/11, PDF schema 6/6, runtime producer 6/6,
service/result checker 35/35 with two Linux-only filesystem tests skipped, and
the full source-guard sweep passes.
No capability record was promoted; the authoritative records file remains
empty and certified qualification is still blocked by the unavailable Linux
x86-64 runner and other roadmap gates.

Follow-on ingress-binding correction (2026-09-08): the service qualification
script's five edge legacy labels no longer masquerade as structured service
records. They invoke the direct clamd legacy wire probe and are typed as
`legacy`; the verifier requires the exact expected command name and outcome
reply, while the acceptance producer intentionally leaves them unmapped until
legacy replies can provide the structured counters and native alert offsets
required by an R04 record. This corrects the workload identity without
changing the empty authoritative records state.

Follow-on evidence-reader audit:

- The PDF object-stream evidence checker, sparse-boundary oracle, and service
  workload/oracle verifier now all use strict TSV parsing and convert malformed
  quoting into their normal fail-closed validation errors.
- Added regressions for each reader. The focused PDF schema suite passes 5/5,
  the boundary-oracle suite passes 5/5, and the service workload suite passes
  22 tests with its 2 Linux-only filesystem tests skipped on this host.
- The shared acceptance, service producer, runtime producer, and snapshot
  suites remain green. No qualification record or capability status changed.

Follow-on service TSV-ingress correction (2026-09-08): the service
workload/oracle reader now rejects wrong-width rows and empty fields while
reading the file, before any later row indexing or evidence access. Added
regressions cover both cases. The service workload suite passes 27 tests with
two Linux-only filesystem tests skipped, and the complete source-guard sweep
passes. No qualification record or capability status changed.

Follow-on generic completion-contract correction (2026-09-08): generic
library, matcher, and feature mappings use a `complete` case suffix, but that
suffix had not been bound to the required `COMPLETE` outcome. The validator
now rejects detection, limit, unsupported, and fault outcomes under that
generic case ID. A regression covers the full record path with a contradictory
detection, and the focused R04 schema suite passes 11/11. The complete source
guard sweep also passes; no qualification record or capability status changed.

Follow-on total-suffix contract correction (2026-09-08): the suffix audit
found that feature `enabled` and R09 `required-behavior` cases were also
generated without an outcome contract. Both now allow only complete or
detection-terminated results, and records with any unknown case suffix fail
closed. The focused R04 schema suite passes 12/12, including generated-suffix
coverage; the complete source guard sweep remains green.

Development service record integration (2026-09-09):

- The existing ARM64 Debug build was run inside the available Docker runtime
  with the development service producer. It exercised the six structured
  daemon REPORT commands (`SCAN`, `CONTSCAN`, `MULTISCAN`, `ALLMATCHSCAN`,
  `FILDES`, and `INSTREAM`) plus `clamdscan --fdpass` and `clamdscan --stream`.
  Each mode produced clean, detection, and limit records, for 24 records total.
- The records were independently revalidated with
  `largefile_acceptance_cases.py --check-records --evidence-root`; exit 0,
  with all 24 retained fixture, oracle, database, report, log, configuration,
  source-manifest, and build-identity bindings intact. The records file hash is
  `4b2d864b14916807c67c928766f7403ce7d35cbe19d91de93096b3ae4d6e2407`.
  The bound source manifest, build identity, and CMake cache hashes are
  `24fb95df5c861cce90acd00d8311020d4f0c48b7375744ef4e5cf7e3c577c7f3`,
  `80b78f4bfe4525f8df4909c3714f79d5a401a8d60d84124a509543469327d82c`, and
  `9b82dbf4f5d10c40e4a31d83ff5c8a3d6ebb0da20b5b7473ebf2f88668cf8fc6`.
- Evidence is retained outside the source tree at
  `/private/tmp/clamav-r04-service-capture-20260909`. It is Linux-aarch64
  development evidence with a 64 MiB envelope; it does not populate the
  authoritative records file or qualify any capability.

This closes a real development producer/validator loop for the covered service
modes. Clean, exact late-marker, full-size, certified, sanitizer, milter,
fanotify, and remaining capability-specific records remain open.

Development lifecycle evidence integration (2026-09-09):

- Each outcome group now retains a `provenance/service-lifecycle-{clean,detection,limit}.tsv`
  artifact containing PING health before and after the cases, PID-file presence
  after startup, daemon-running state before stop, process exit after stop, and
  observed absence of both socket and PID file after cleanup.
- The development producer now binds the corresponding lifecycle artifact and
  carries `daemon-health=ping-before-and-after;cleanup=lifecycle-verified` in
  `resource_phase`. A failure in either health or cleanup is fail-closed in the
  producer rather than being recorded as a passing case; cleanup is observed
  before the evidence bundle's temporary-directory teardown, so a stale socket
  or PID file cannot be hidden by the harness. The retained 24-record bundle
  above predates this enhancement and remains accepted by the generic validator;
  a fresh capture is required to emit the new lifecycle artifacts.
- The focused lifecycle test passed 5/5 and the complete local tools suite
  passed 145 tests with 2 expected skips. This remains development ARM64/64 MiB
  evidence and does not populate authoritative records or qualify a capability.

Follow-on R04 lifecycle fixture-binding correction (2026-09-11): lifecycle-bound
acceptance records now require a named `fixture_role` and the
`provenance/service-inputs-before.json` identity sidecar. A retained fixture
artifact alone cannot satisfy a record that claims daemon health/cleanup
lifecycle evidence. Added regressions for missing role and missing sidecar;
the focused acceptance schema passes 12/12, the full tools suite passes
145 tests with 2 expected skips, and the complete source guard passes. The
authoritative acceptance-record file remains empty; no capability status was
promoted and certified Linux x86-64/full-size qualification remains blocked.
