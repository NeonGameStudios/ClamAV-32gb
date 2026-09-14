# 32 GiB completion roadmap for a Luna 5.6 executor

Updated: 2026-09-05. This is an execution guide, not a release certificate.

## Start here

The goal is to finish the contract in [PLAN.md](../PLAN.md), not merely make tests green or increase the number of capability rows. Use this guide to give one bounded task at a time to a Luna 5.6 subagent. A coordinator owns integration, the acceptance specification, source identity and final qualification. Larger cards below are milestones: split them into the indicated slices before delegation. No model can guarantee completion of unknown parser work; a failed acceptance case becomes a concrete next task, not permission to weaken the contract.

Canonical checkout on the current host: `<repository-root>`, branch `largefile-roadmap-qualification`. The similarly named `<related-checkout>` is a separate, stale source folder. The existing container's `/src` mount is not sufficient proof of current source. On another runner use the actual transferred candidate's absolute path, never these host paths blindly.

Read in order:

1. Repository `AGENTS.md` and any applicable parent instructions.
2. [Current snapshot](../32gb-current-snapshot.md), then this guide.
3. [PLAN.md](../PLAN.md), the authoritative product contract.
4. [Recent completed tooling](largefile-qualification-followups.md) and [input policy](largefile-service-input-policy.md).
5. The assigned capability rows in [largefile-capabilities.tsv](largefile-capabilities.tsv) and their source files. Use [audit1.md](../audit1.md) and [status history](../32gb-status.md) only for targeted history; old dated claims are not current proof.

### Recorded starting point; recompute before work

- Base HEAD: `ff8905891b2b58a66c71859ab2c807cc4dee2dec`; the working tree also contains uncommitted fixes and new files. A checkout of HEAD alone loses those fixes.
- Recorded before the R09 slice: 597 capability rows, 0 qualified, 143 bounded, 433 pending, 21 unsupported, and 583 release blockers. Counts are not percentage complete; recompute from the current snapshot before acting.
- Already implemented: strict materialized/exact-edge input binding, mutation checks, contradictory outcome rejection, exact signature log parsing, a separate sparse 32 GiB + 1 FILDESREPORT probe, and a short snapshot generator. Do not reimplement them.
- Latest development verification includes the current-source ARM64 Release and ASan/UBSan control matrices, the current Release application smoke, and focused parser slices. The reader-backed `rust_onenote` group passes 4/4 in both Release and sanitizer builds, including a logical input above the former 256-MiB whole-input cap and streamed attachment detection. This is ARM64 development evidence, not certified x86-64 release evidence.
- No current-source live report from the exact oversized qualification probe exists: the dedicated qualification option is correctly restricted to the certified Linux x86-64 profile, and the current ARM64 container cannot satisfy that contract. A stale binary must not be substituted.
- Known open areas include certified exact/materialized 32-GiB qualification, contiguous parser/unpacker paths that still retain documented bounds, independent bytecode format-8 execution, capability-specific proof coverage, full materialized ingress/parser qualification, PCRE memory phases, fanotify and the production canary. The bounded modern OneNote reader path is implemented and locally verified; its full-size qualification remains open.

## What finished means

All of these are mandatory unless the user explicitly changes PLAN.md:

| Requirement | Passing behavior |
| --- | --- |
| Input boundary | Accept 0 through 34,359,738,368 bytes inclusive; reject 34,359,738,369 bytes without a clean-prefix result. |
| Deep inspection | Every structurally confirmed supported layer is inspected through the applicable limits; valid supported content cannot pass merely by being marked incomplete. |
| Results | Clean requires success, clean/trusted verdict, `COMPLETE`, and no required skipped operation. Detections may terminate work; incomplete, resource, unsupported and malformed results stay visible and non-cacheable. |
| Shared budgets | 64 GiB logical content, 256 GiB matcher work, 64 GiB temporary staging, checked file/recursion limits and a four-hour scan deadline. Normalized/retyped views do not double-charge logical bytes. |
| Memory | Keep the 1 GiB individual-allocation guard; full-subject PCRE is the specified exception. Peak process RSS <=40 GiB during PCRE, then <12 GiB before deep parsing; no swap, OOM or sanitizer diagnostics. |
| Admission | Certified Linux x86-64 build and features; >=48 GiB effective available/cgroup memory and >=68 GiB free disk-backed temporary space. Provision extra storage for retained fixtures, build trees and evidence. |
| Ingress | Modern library path/fd/fmap, CLI file/stdin, daemon command families, clamdscan modes, milter and privileged on-access all satisfy their applicable acceptance cases. |
| Scheduling | MaxThreads/OnAccessMaxThreads=1, MaxQueue=2; a second request waits without premature staging or resource reservation. |
| Evidence | Current immutable source/build/dependency/database identities; Release plus C/Rust sanitizer evidence, full materialized edges, exact signatures/offsets, resource phases, cleanup and daemon health. |
| Release | Every required capability has verified capability-specific cases; readiness passes on the final default-enabled candidate, and the authorized production canary passes. |

Keep the 14 explicitly allowlisted unsupported exclusions. The earlier R09
analysis identified seven rows that must remain in scope: matcher admission
and fuzzy-image boundaries, plus `CL_TYPE_AI_MODEL`, `CL_TYPE_IGNORED`,
`CL_TYPE_PYTHON_COMPILED`, `CL_TYPE_RAR`, and `CL_TYPE_RARSFX`. The current
manifest records those rows as `pending` rather than `kind=unsupported`, while
the 14 `kind=unsupported` rows are the explicit first-release exclusions.
That classification does not qualify the pending behavior or release: every
pending row still needs its required implementation and capability-specific
evidence. RAR backend absence is distinct from unsupported encrypted content
with no key.

The R09 development slice keeps these rows in scope with fail-visible
admission, raw-matching, parser-policy, RAR backend, and fuzzy-image boundary
checks. This resolves the manifest classification contradiction without
claiming release qualification; full parser/matcher implementation where still
needed and certified evidence remain mandatory.

## Working rules and task handoff

- Preserve existing changes. Read `git status --short`, inspect the diff and record what predates your task. Never reset, clean, overwrite another task's work, or silently switch branches.
- Avoid software installation. If an indispensable dependency is absent, first identify an existing authorized runner/toolchain. Before any installation, follow the user's required notice exactly:

  ```text
  WARNING - WE WILL BE INSTALLING SOFTWARE NOT CURRENTLY INSTALLED - WARNING
  <name of software>
  WARNING - WE WILL BE INSTALLING SOFTWARE NOT CURRENTLY INSTALLED - WARNING
  ```

- Do not update, enable, dispatch, rerun or otherwise trigger GitHub `CMake Build`, including its workflow file or a triggering push, without explicit user consent. Keep it disabled. Routine commits stay local; pushes also obey the 30-minute newest-commit age rule. This guide does not authorize a push or deployment.
- The coordinator integrates shared reader/spool/report interface changes before parallel dependent family work; isolated worktrees still require integration and revalidation. Assign one writer per file or use isolated worktrees based on a coordinator-prepared candidate that includes the existing changes. The coordinator owns shared manifest, gate and integration edits. Do not start multiple full-size workloads on one qualification host.
- First reproduce the specific gap with a meaningful control. Implement the smallest coherent slice. Run relevant tests against coherently rebuilt current binaries. A source guard, mocked response, tiny fixture or object-file compilation is not runtime/full-size evidence.
- Do not raise local caps, suppress required parsers, weaken an assertion, change expected output to match a failure, or relabel unsupported rows to obtain a pass.
- Use lower-concurrency builds after investigating SIGKILL/resource evidence. Do not retry an unchanged resource-blocked build indefinitely or claim its old executable was rebuilt.
- If prerequisites fail, record the exact command, exit status, resource/source identity, reason and next action. Continue independent authorized tasks; leave dependent work pending.

For every delegated slice record this small task receipt outside large binary evidence bundles (suggested future location: `docs/largefile-task-receipts/<task-id>.md`):

```text
Task ID / parent milestone:
Exact capability kind:id list:
Starting commit and working-tree/source manifest identity:
Prerequisites verified:
Owned files and excluded shared files:
Observed failing case and expected behavior:
Changes made:
Commands, exits, logs and fixture/database hashes:
Development tests passed:
Full-size/certified evidence produced, or explicitly not run:
Remaining failures / next slice:
State: not-started | active | implemented | development-verified | qualified | blocked
```

`implemented` and `development-verified` do not qualify a capability. Only the coordinator promotes status after independent evidence verification. Split any slice that cannot be explained with one concrete input/expected-output example; aim for roughly 1–4 hours per slice, not a promised time limit for the whole milestone.

## Dependency order

1. **R00** establish the actual source and remaining work.
2. **R01–R03** repair provenance/gate prerequisites and obtain a usable build. R03 host discovery and R02 specification/unit work may run alongside R01. Freeze the first immutable build candidate after R01; complete R02 live log checks after R03 provides fresh binaries.
3. **R04–R05** specify capability cases and fixtures, then validate one real service path.
4. **R06–R10** close implementation families in bounded slices; use the same case schema. R06, R07 and distinct R08 families may run independently after shared reader/spool contracts are understood.
5. **R11** qualify one complete vertical slice before multiplying full-size runs.
6. **R12–R14** complete the matrix, on-access/resource evidence and production canary.
7. **R15** activate defaults, requalify the actual final source and close release.

When the runner is unavailable, work on R01/R02/R04, fixture generation and bounded implementation tests. Do not spend repeated rounds adding textual source guards while all valid-content milestones remain open.

## Task cards

### R00 — Freeze the real starting point and assign coverage

**Inputs:** current snapshot, working tree, capability TSV, this guide.

**Actions:** verify the canonical root/branch; preserve and review every tracked/untracked task file. Record `git diff --stat` and the relevant diffs. Record this dirty starting state without claiming it is an immutable qualification candidate. Review which changes belong in the candidate; freeze the first immutable build candidate only after R01 resolves provenance cycles. The current Git-mode source-manifest helper hashes tracked files only: a manifest generated before adding new source files is not the complete candidate. Use a reviewed local commit or the gate-supported immutable source-snapshot path; never delete the changes to obtain a clean tree.

**Deliver:** task ledger and starting working-tree identity, plus a coverage assignment for every `(kind,id)` in the TSV. Assign all 426 library rows as well as matchers, features, ingress and parsers; a parser-only checklist is insufficient. Unknown ownership gets an explicit triage slice.

**Done:** no unassigned required row, no missing new helper in the candidate, and the build/source root is unambiguous. No qualification label changes yet.

### R01 — Make snapshot and evidence provenance compatible with commits

**Entry points:** `tools/largefile_status_snapshot.py`, its tests, `largefile_source_manifest.sh`, `largefile_source_guards.sh`, `largefile_release_readiness.sh`.

**Gap:** the tracked generated snapshot currently embeds HEAD and freshness compares HEAD. A commit changes HEAD after generation. In addition, snapshot text hashes the capability manifest, while the release gate filters only the manifest itself when comparing source: promotion metadata can change the snapshot and hence the supposedly fixed source identity. Resolve both dependency cycles before freezing qualification evidence.

**Slices:** (a) create an isolated temporary Git-repository regression demonstrating generate -> commit -> freshness; (b) define deterministic tracked snapshot content and separate external run provenance; (c) test promotion of evidence metadata without creating a self-referential source hash. Prefer separating generated dashboards/release metadata from executable source identity. If exclusions are necessary, make them narrow and shared; actual code, build settings, fixture definitions and verifier changes must invalidate evidence.

**Done:** normal commits do not force an endless snapshot refresh; release binding can be completed without a hash fixed-point; changing any executable acceptance input still rejects stale evidence. Existing stale-manifest and tamper tests remain effective.

### R02 — Reconcile resource policy and genuine log/report formats

**Entry points:** PLAN.md, `largefile_runtime_gate.sh`, `largefile_runtime_evidence_check.sh`, `largefile_release_readiness.sh`, `largefile_service_qualification.sh`, `largefile_service_workload_check.py`, `clamdscan/client.c` and report client handling.

**Gap A:** runtime producer/verifier/readiness currently hard-code 33,554,432 KiB RSS (32 GiB), while PLAN.md permits 40 GiB during full-subject PCRE and requires <12 GiB afterward. Document whether this is an intentional stricter subset gate or an incompatible full-PCRE gate. Implement explicit workload/phase budgets in both producer and independent verifier; preserve a stricter subcase where valid. Do not change a number merely to fit a failing scan.

**Gap B (live checks depend on R03):** exact-name validation expects `input: Signature FOUND`, but some report frontends emit only `input: FOUND`. Before R03, inspect source and add format controls only. After R03, capture the actual outputs from a freshly built daemon/client; never use the stale daemon to finish this card. Preserve exact structured alert/offset binding and define where console-name proof is required. Either emit a truthful exact signature for that frontend or use an explicitly typed structured-report evidence path; a bare FOUND substring must never substitute for exact detection proof.

**Done:** authentic clean, exact detection, limit and error outputs pass/fail as specified; unrelated heuristics, wrong names/offsets, partial scans and missed memory phases fail. Add producer/post-run parity regression controls.

### R03 — Establish the certified build and reusable runner

**Entry points:** `tools/largefile_host_preflight.sh`, `clamd/largefile_admission.c`, CMake options, pinned Rust toolchain, existing build configurations and sanitizer verification in `largefile_runtime_gate.sh`.

**Slices:** (a) locate authorized Sonic1 or equivalent Linux x86-64 runner and record actual resources/tools without assuming connectivity; (b) configure an out-of-tree Release build from the frozen candidate with the certified optional features, including required UnRAR/milter/PCRE/bytecode support; (c) build C and Rust coherently and run its discovered CTest suite; (d) produce separate C ASan/UBSan and required Rust address-instrumented artifacts using the gate's checked toolchain contract.

Use installed dependencies; do not disable a required feature to make the build pass. Keep development defaults opt-in while using the explicit qualification configuration. Record CMakeCache, compile_commands, compiler/Rust versions, source manifest, binary/shared-library hashes and database identities. A C-only sanitizer pass does not prove Rust instrumentation.

**Done:** source/build identities agree, required binaries and features exist, fresh Release and sanitizer suites pass, admission checks pass, and test logs are retained outside the source tree. This establishes build readiness only: do not promote capabilities until R04 case-bound evidence is independently verified. If runner/toolchain is unavailable, this milestone is blocked; mocked success is forbidden.

### R04 — Require capability-specific acceptance records

**Entry points:** `largefile_release_readiness.sh` (`verify_capability_binding`, `verify_qualified_evidence`), runtime/service verifiers, manifest validator and readiness regression tests.

**Gap:** today's proof header identifies a capability, but the generic runtime/service verifier does not consume that identity to require its actual cases. A renamed self-bound header is insufficient proof of that parser or matcher.

**Ownership:** R04 owns the case schema and its generic verification/integration; R13 owns the privileged fanotify runner and kernel-event verifier. Missing R13 evidence must block qualification, not block defining its required schema.

**Slices:** (a) define a reviewed capability-to-required-case mapping with complete TSV coverage; (b) define case records and a verifier; (c) integrate producer records; (d) make authoritative readiness consume capability identity and verify all required cases. Proposed new files such as `docs/largefile-acceptance-cases.tsv` do not exist yet: create their schemas and validators in this task, do not invent a command and assume it works.

A case record must bind capability and case IDs, source/build/config/platform, independent fixture/oracle identity, DB identities, actual exit/verdict/completion/reason, exact alert/offset when applicable, counters, sanitizer state, resource phases, health, cleanup and retained artifacts. Derived views must identify their parent fixture/offset semantics. Permit shared execution artifacts only when each capability's required cases are genuinely present.

**Done:** complete coverage including non-parser rows; passing case records for one family cannot qualify another. Recomputed-checksum controls reject missing/wrong cases, renamed generic proofs, stale binaries, non-materialized required fixtures, missing sanitizer/resource/fanotify proof, and substituted expected results.

### R05 — Finish fixture/oracle tools and prove the new oversized probe live

**Entry points:** `largefile_boundary_corpus.sh`, existing `largefile_*_fixture.py` tools, `largefile_service_oversize.py`, workload checker, `unit_tests/milter_protocol_test.py`.

The coordinator selects the first family and approves full-size resource scheduling. Establish structural validity independently of the scanner: retain format-spec-derived generator assertions and an independent parser/inspection oracle where available, with hashes and expected member layout. If validity cannot be established, the fixture is not an acceptance control.

**Slices:** (a) one deterministic valid fixture and independently derived oracle per selected family; (b) full allocation/SEEK_HOLE checks for materialized fixtures; (c) current-source FILDESREPORT oversize run, with alerts both on and off; (d) protocol/report corrections if the real result differs from the mocked contract.

For every family specify clean complete, late-marker detection, malformed-confirmed, unsupported codec/encryption where applicable, weak false-candidate, shared-limit, read/write/allocation/timeout/cancellation cases. Include old-cap boundaries and >4-GiB offsets. Never derive the expected signature/offset/completion from the scanner output being tested.

The sparse probe is exactly 32 GiB + 1 and tests metadata admission only. Retain its exact reason, zero parser/matcher/logical/staging work, stable metadata, cleanup and pre/post PONG proof. It does not replace the fully allocated release oversized case or stream overflow testing.

**Done:** reproducible fixture/oracle hashes, controls that catch truncation/partial extraction, and a genuine current-source live probe report. Full-size family evidence remains a later milestone.

### R06 — Complete reader-backed modern OneNote

**Entry points:** `libclamav_rust/src/onenote.rs`, `scanners.rs`, `fmap.rs`; relevant Rust tests and C FFI/report tests. Existing C TCases include `rust_onenote` and `onenote`; inspect their registration in `unit_tests/check_clamav.c` before filtering. Read the current modern parser dependency/API before designing changes.

**Slices:** (a) demonstrate the modern path's 256-MiB whole-input refusal with a structurally valid fixture; (b) implement reader/seek-backed traversal or a bounded adapter at one parsing boundary; (c) spool member output and connect quotas, deadline and error/cleanup propagation; (d) integrate the modern path without regressing legacy extraction.

Preserve legacy fallback semantics: full OneNote magic with no valid legacy record remains confirmed incomplete/non-cacheable, not clean. Do not just raise the whole-buffer cap or use a giant Vec/mmap as an alleged streaming implementation. Keep format-defined widths distinct from containing-file offsets.

**Done:** valid modern input beyond the former cap completes, late child content is detected at the independently expected offset, short reads/truncation/overflows/quota failures stay incomplete and non-cacheable, and reservations/spools are released. Full materialized edge qualification is still required under R12.

### R07 — Qualify independent bytecode format 8

**Entry points:** `docs/bytecode-abi-v2.md`, `unit_tests/check_bytecode.c`, `unit_tests/clamscan/bytecode_test.py`, engine bytecode files and `clambc`.

**Slices:** (a) locate an already available compatible external compiler/artifact; if absent, mark that slice blocked and identify the exact dependency for the coordinator/user, without installing, downloading or contacting anyone; (b) retain source, compiler identity and independently compiled format-8 fixture hash; (c) exercise v2 globals and cross-4-GiB read/seek/search and late offsets through interpreter and JIT; (d) test mixed v1/v2 applicability and official production bytecode behavior.

**Done:** actual independent compiled module executes correctly in both runtimes on current source, with exact result/offset and sanitizer proof. Mutating a format-7 header or testing a host API with a synthetic map is only a negative/unit control. v1 inability to represent an applicable layer remains explicit incomplete; do not emulate arbitrary v1 semantics with unrelated windows.

### R08 — Close the remaining parser, unpacker and detector implementation gaps

**Entry points:** each capability row's `source`, scanner dispatch in `libclamav/scanners.c`, common readers/spools/accounting, existing focused fixtures/tests.

Create one child task per family and then per concrete gap; this card is not a single delegated implementation task:

| Family | First inspection targets / necessary behavior |
| --- | --- |
| Archive/executable | 7-Zip solid, ZIP/SFX, NSIS, AutoIt, EGG, PE unpackers, ARJ/CAB/InstallShield; bounded extraction, native outer coordinates, authoritative lengths and exact late members. |
| Rust | LHA/LZH and ALZ along with R06 OneNote; borrowed windows/Read+Seek, bounded output, FFI error propagation. |
| Documents/normalization | Mail/MIME, PDF streams/ObjStm, XDP/HWPML, HTML/script; complete spool output, shared accounting and late attachments. Reuse PDF qualification helpers where applicable. |
| Containers/filesystems/media | ISO/UDF/HFS+, partition/image formats, XAR/DMG, OLE/VBA, image/media and optional decoders; inspect every dispatch branch, including malformed and weak-recognition behavior. |
| Matchers/features/library | Hash, AC/BM, logical, YARA, fuzzy-image, PCRE, bytecode, callbacks/cache/report APIs and each optional build feature. Preserve outer raw matching and native offsets. |

For each assigned row: classify actual implementation versus evidence gap; cite the exact call path; implement only demonstrated missing behavior; add valid completion and late detection in addition to failure controls. Apply candidate/confirmed/rejected embedded recognition without allowing confirmed malformed layers to become clean. Verify reader/spool quotas, temporary cleanup, callback termination, allocation failure and non-cacheability.

**Done per slice:** the former failing case now satisfies the contract under coherent development tests. **Done for R08:** every required row has implementation coverage and an R04 acceptance-case assignment; unresolved work is explicit, never hidden behind a family summary.

### R09 — Resolve all seven required unsupported rows

**Dependencies:** R04 coverage; relevant R08 work and required backends in R03.

Split into RAR/RARSFX backend qualification, fuzzy-image implementation/admission, and recognized AI-model/compiled-Python/ignored-type policy or parser work. Check the precise classifier and expected semantics rather than assuming all recognized formats promise a parser. Present any actual PLAN/manifest conflict with affected IDs and user-visible behavior to the coordinator for a user scope decision. No unilateral exclusion is allowed.

**Done:** each row has implemented and verified required behavior, or an explicit user-approved contract change with matching manifest/gate/tests/docs. Until then full-roadmap completion is blocked.

### R10 — Complete ingress parity and private service behavior

**Entry points:** modern library APIs/tests, `clamscan`, `clamd`, `clamdscan`, `clamav-milter`, service producer/verifier and protocol tests.

Split by ingress, sharing the R04 record format. Cover path/fd/fmap; CLI file/stdin; SCAN/CONTSCAN/MULTISCAN/ALLMATCHSCAN, FILDES/INSTREAM and their supported REPORT counterparts; clamdscan default/fdpass/stream/multiscan combinations; milter. Verify dormant STREAM removal or repaired behavior as PLAN requires. Test clean complete, exact malware detection, exact limit rejection and operational failure; compare normalized reports while retaining original logs.

Unknown-size streams must reject byte 32 GiB + 1 and remove partial staging. Known-size descriptors must reject before content work. Milter must distinguish malware from incomplete/resource actions. With one worker, MULTISCAN must function and two simultaneous requests must prove queuing without early staging/reservation.

**Done:** required mode coverage is machine-checked, authentic R02 log/report behavior passes, cleanup and daemon health are measured. A generic service success does not cover on-access; that is R13.

### R11 — Qualify one complete vertical slice

The coordinator chooses a currently implemented family with independently validated fixtures and schedules full-size resource use (for example ZIP, after checking its actual status). This is the first release-style end-to-end proof, not another unit test.

Run it on R03's frozen candidate through applicable library/CLI/daemon/client modes with production databases plus separately identified custom signatures, materialized exact edges, Release/sanitizer parity, exact tail/member results and measured resources. Feed its real records into R04's capability-specific verifier; adversarially remove a required case and require failure.

**Done:** that family's full required proof verifies and cannot qualify an unrelated family. Document reusable runner commands and measured runtimes/storage, then scale the matrix. If this fails, fix the pipeline before launching all families.

### R12 — Complete the full parser/matcher/feature acceptance matrix

Execute every R04 case, grouping shared genuine runs where justified. Every parser dispatch branch needs a 32-GiB outer-coordinate fixture; every implementation family also needs a fully materialized exact-edge case. Use smaller homologous fixtures for exhaustive malformed/fault states. Include exact-tail native/hash/logical/YARA/PCRE/bytecode-v2 and nested member/attachment/embedded-PE markers.

Record warm/cold cache behavior, complete valid controls separately from expected incomplete cases, production database hashes, Release and sanitizer results and daemon health after each case. Missing features/tests or sanitizer skips are blockers. Diagnose and fix any failing implementation, rebuild coherently, invalidate affected stale evidence and rerun against the final candidate.

**Done:** no required capability/case is absent. Unit-test quantity, sparse scans and historical ARM64 logs do not meet this milestone.

### R13 — Measure PCRE memory phases, queue resources and real fanotify

Split these independent cases into separate tasks with a single coordinator controlling full-size host use. On-access entry points include `clamonacc/client/client.c`, `clamonacc/client/protocol.c`, `clamonacc/scan/thread.c` and `clamonacc/fanotif/fanotif.c`; the tracked ingress capability is `on-access:permission`.

- PCRE: capture full subject residency and peak RSS, then demonstrate RSS <12 GiB after subject/window release and before deep parsing starts. Sample total process/tree metrics appropriately; report counters alone are not RSS evidence. Verify full-subject exact tail matches, exhaustion as incomplete and the shared ledger.
- Resource/queue: total temporary usage <=64 GiB including INSTREAM plus child spools; disk-backed staging; no swap/OOM; deadlines, cancellation and no leaks. Prove the second request did not reserve/stage while the first occupied the single worker. Runtime stress with multiple independent scanners is distinct from this daemon queue test.
- Fanotify: on a disposable authorized Linux test mount with real permissions, verify kernel permission allow for a completed clean case, deny for malware and for incomplete/resource/timeout/parser failures. Verify monitoring-only semantics separately. Keep a recovery/cleanup path for the private test processes and mounts. No need to alter production on-access policy.

**Done:** independent verifiers require the real phase, queue and kernel-event evidence; mocks only test the harness. Unavailable privilege or observability is a blocker, not a skip-to-pass.

### R14 — Production canary and candidate review

Use authorized real files and current production CVDs on Sonic1 or the explicitly accepted equivalent. Keep this a private canary; changing production deployment is a separate authorized action. Record per-parser completion, limits, latency, RSS/PSS/VAS, page faults, I/O, temporary peaks and report hashes. Compare expected known behavior and investigate every unexplained incomplete result or regression.

**Done:** all applicable PLAN acceptance criteria pass on an immutable candidate; an independent review checks completeness of the R04 matrix and retained evidence, not only `qualification_result=pass` text. No required unsupported row remains unresolved.

### R15 — Enable defaults and requalify the actual release

Only after R11–R14 demonstrate the candidate contract, prepare the final default activation in `CMakeOptions.cmake` and relevant option/sample/man/API documentation; verify startup capability-manifest output. Follow PLAN's exact defaults and retain the explicit platform limitation.

Default activation changes the source/configuration: produce a new immutable candidate, rebuild Release/sanitizers, rebind and rerun required acceptance evidence. Do not reuse a previous candidate hash by editing its metadata. R01 must allow honest final qualification bookkeeping without source-hash cycles.

**Done:** the authoritative readiness command exits 0 with verified capability-specific evidence on the final candidate; snapshot and task ledger agree; all PLAN acceptance requirements, including the final candidate canary, are satisfied. Publish a concise release evidence index and known deliberate exclusions. Keep GitHub CMake disabled unless separately authorized. Report readiness to the user; pushing, publishing or production rollout follows actual user authorization.

## Verified command entry points

These are existing interfaces at this guide's date. Read each script's header again before use. Execute commands individually and retain their real exit statuses; do not pipe a failing test into a successful `tail` and call it passed. Large gates are expensive and require the preceding task prerequisites.

Local source checks (run from the canonical checkout):

```sh
git rev-parse --show-toplevel
git branch --show-current
git status --short
sh tools/largefile_release_readiness.sh --status
sh tools/largefile_service_evidence_check_test.sh
python3 -B tools/largefile_status_snapshot_test.py
sh tools/largefile_source_guards.sh
git diff --check
```

The current `--status` exit 1 means release-blocked, not a command malfunction. Exit 2 is an invocation/validation error. Do not treat either as release success. Run other unit/CTest cases appropriate to changed code, not merely these tool tests.

Runner templates: the coordinator must first assign real absolute paths to the variables below, outside the source tree for builds, fixtures and output. They are deliberately not invented host addresses or a complete build recipe.

```sh
sh tools/largefile_host_preflight.sh "$PREFLIGHT_OUT" 50331648
sh tools/largefile_source_manifest.sh "$SOURCE_ROOT" "$SOURCE_MANIFEST_OUT"
ctest --test-dir "$RELEASE_BUILD" -N
ctest --test-dir "$RELEASE_BUILD" --output-on-failure
ctest --test-dir "$SANITIZER_BUILD" --output-on-failure
sh tools/largefile_service_qualification.sh "$RELEASE_BUILD" "$SERVICE_OUT" \
    "$PRODUCTION_DB" "$PRODUCTION_FILE" "$MATERIALIZED_FILE" "$EXPANSION_FILE" \
    "$EDGE_FILE" "$EDGE_DB" "$ORACLE_MANIFEST"
sh tools/largefile_service_evidence_check.sh "$SERVICE_OUT" "$RELEASE_BUILD"
python3 tools/largefile_service_oversize.py "$PRIVATE_CLAMD_SOCKET" \
    "$OVERSIZE_REPORT_OUT" "$PRIVATE_TEMP_DIR" 60
# Final gate only after R15 prerequisites; currently expected to report blocked.
sh tools/largefile_release_readiness.sh
```

The library exact-edge CTest is `largefile_library_exact_32g`, registered only when `ENABLE_LARGE_FILE_QUALIFICATION_TEST` is enabled; absence is not a passing test. Existing focused C tests can use `CK_RUN_CASE=<verified-case-name> ctest -R '^libclamav$' --output-on-failure` from the coherent build directory. Discover case names in source instead of guessing.

`largefile_runtime_gate.sh` currently takes `CLAMSCAN OUTPUT_DIRECTORY RSS_BUDGET_KB` and requires explicit sanitizer, memory-headroom and provenance settings documented in its header. R02 must resolve its RSS contract before prescribing a full-PCRE release invocation. Do not bypass it using `--test-manifest`, disabled sanitizers, smaller production constants or a non-certified platform. An early authoritative readiness run is diagnostic and currently exits 1; it must not be treated as task failure if the assigned task never claimed release qualification. Only a fully verified final candidate may be called ready. Fanotify and capability-case runner commands must be implemented and documented under R04/R13; no complete existing command is claimed here.

## Copy/paste prompt for one Luna 5.6 subagent

The coordinator replaces every angle-bracket field before dispatch. Start with R00; after that choose a ready slice, not the entire roadmap.

```text
Work in <absolute canonical or isolated candidate path> on <actual branch/source identity>.
Read AGENTS.md and docs/32gb-luna-execution-roadmap.md, then PLAN.md and the assigned capability rows.
Execute only <task ID and bounded slice>, for capabilities <exact kind:id list>.
Concrete input/failure: <reproduction and expected behavior>.
Prerequisites already verified: <source, dependencies, runner/build identity>.
You own <explicit files>. Shared files owned by the coordinator: <files>.
Preserve existing changes. Do not weaken limits, oracles, coverage or failure semantics.
Use existing tools; follow the required installation notice if a dependency is truly missing.
Do not push, deploy, change/trigger GitHub CMake, or launch unapproved production activity.
Acceptance checks: <exact focused tests plus required runtime cases and output paths>.
Complete the implementation and checks within this scope; if it expands, leave a precise next slice.
Return a task receipt with changes, actual commands/exits, evidence identity, limitations and next action.
Do not mark a capability qualified from unit, mocked, sparse-only, stale-source or ARM64 evidence.
```
