# 32 GiB roadmap progress review — 2026-09-04

Reviewed repository: `/Volumes/512gbNVME/github-external/ClamAV-32gb`  
Branch: `largefile-roadmap-qualification`  
Reviewed HEAD: `ff8905891b2b58a66c71859ab2c807cc4dee2dec`  
Comparison baseline: `5aee0970e23c6032997023b76ceb3be4d9277fb4` (August 24 end of day).

**Assessment: useful implementation progress is continuing, but progress toward the full release contract is not yet demonstrated. The next phase needs to close implementation and end-to-end qualification milestones. Continuing focused hardening and status refreshes alone will not finish PLAN.md.** There is no dated delivery commitment in PLAN.md, so this review cannot establish that a calendar deadline was missed.

The current documents correctly say the branch is not release-qualified. This review does not dispute that warning or equate explicit incomplete results with successful full scans.

## Verified progress and current position

The local readiness command reproduces the current summary:

| Measure | August 24 baseline | Reviewed HEAD |
| --- | ---: | ---: |
| Capability rows | 184 | 597 |
| Qualified | 0 | 0 |
| Bounded | 38 | 143 |
| Pending | 122 | 433 |
| Unsupported | 24 | 21 |

At HEAD, **583 rows block release**, including seven required rows marked unsupported. All 80 parser rows block release: 75 pending and five unsupported. The summary's 75 enabled parser rows and the gate's `parser_blocked=80` are therefore consistent when the five unsupported rows are included.

Between these revisions, 418 rows were added and five removed. Of 179 retained rows, none advanced to qualified or from pending to bounded; one changed from pending to unsupported (`CL_TYPE_IGNORED`). The larger blocker inventory represents broader tracking as well as unfinished work; it is not evidence that 413 new implementation defects appeared, and these counts are not a percentage-complete estimate.

There are substantive recent fixes. Commit `b2a07319` repairs TNEF attachment-blob admission so ordinary extraction is not rejected before assigning its filename. Commit `b2d3555d` preserves terminal alert-callback decisions in `libclamav/others.c`, preventing ZIP processing from continuing after a stop/trust decision. These are concrete correctness improvements. The recent coherent relink also exposed and corrected PDF/ARJ build defects that stale linked artifacts had missed (`audit1.md:134`).

The opt-in large-file defaults remain OFF in `CMakeOptions.cmake:35`, consistent with PLAN.md's requirement to activate them only after qualification.

## Where the work is diverging from completion

### 1. Qualification is accumulating as a backlog instead of closing release milestones

The current requirement audit explicitly leaves certified Linux x86-64 execution, complete parser coverage, sanitizer runs, production CVDs, materialized edge fixtures, service parity, resource measurements, and the Sonic1 canary open (`audit1.md:615–642`). The local container inspected during this review is AArch64. Its latest authoritative build uses `ENABLE_UNRAR=OFF` and `ENABLE_LARGE_FILE_DEFAULTS=OFF`. It is useful for development tests but cannot satisfy the certified profile.

The September 4 source refresh is a necessary improvement over stale harnesses. However, neither more source guards nor repeatedly passing small failure cases proves completion of the full 32 GiB workloads. Sonic1 unavailability is reported by the existing documents; this review did not independently retry its SSH connection.

**Fix:** Treat a reproducible, immutable-source Linux x86-64 qualification build as the next release dependency. Restore Sonic1 or arrange an authorized equivalent runner with the required resources and existing toolchain. Complete a coherent C/Rust/CTest and ASan/UBSan baseline there, record source/build/database hashes and configuration, then run successive parser and ingress milestones against that same candidate. Fix failures and rebind affected evidence after changes. Do not promote local ARM64 or historical August evidence to current release certification.

### 2. Safe refusal still substitutes for implementation in required paths

Modern OneNote is a concrete example: `libclamav_rust/src/scanners.rs:985–995` explicitly refuses the modern parser above its whole-input cap; `libclamav_rust/src/fmap.rs:266` sets that cap to **256 MiB**. `libclamav_rust/src/onenote.rs:329–330` still calls `parse_section_buffer` on a borrowed whole-file slice. The legacy reader-backed extractor does not close this modern-parser gap.

That refusal preserves safety, but it does not meet PLAN.md's requirement to inspect supported valid content through 32 GiB under shared limits. The audit also acknowledges legacy contiguous unpacker limitations (`audit1.md:973–990`). Independent format-8 interpreter/JIT bytecode evidence is still absent from the current summary (`32gb-status-summary.md:30–35`).

**Fix:** Make reader-backed modern OneNote parsing and the remaining contiguous parser/unpacker conversions explicit implementation milestones. Preserve the allocation guard and fail-visible behavior while implementing them; simply raising a cap does not solve bounded-memory parsing. Require valid-content completion and late-child detection above the old limit as well as rejection tests. Resolve the seven required unsupported rows under the original contract; any reduction in release scope must be an explicit project decision, not a manifest relabeling.

### 3. The release gate still needs capability-specific acceptance evidence

`tools/largefile_release_readiness.sh:151–167` checks six proof metadata fields, including `qualification_result=pass`. It verifies source and artifact hashes, but then invokes a generic runtime or service verifier without passing the capability ID (`:241–262`). The binding is stronger than an unqualified status label, but it does not require that the evidence contains the tests needed for that particular parser or matcher.

This is a future false-confidence risk, not a claim that today's blocked gate passed. The statement that the generic-evidence loophole is closed in `audit1.md:950` overstates what the current checks establish.

**Fix:** Define required acceptance cases per capability or implementation family and make the verifier consume the capability identity. Require named test records with immutable fixture bindings, expected and observed completion, exact signature/offset where applicable, platform/configuration, sanitizer results, and resource evidence. Share real run artifacts where appropriate, but require each claimed capability's own acceptance cases. A renamed six-line proof must not qualify an unrelated capability. Add rejection controls for that case.

### 4. Service fixture binding does not fully enforce PLAN.md's workload requirements

`tools/largefile_service_workload_check.py:83–112` accepts caller-specified sizes and completion states for its four oracle roles. `:157–168` checks that input size and hash match the oracle, but does not require physical allocation or enforce 32 GiB for the `edge` role. The producer's `oracle_load` follows the same size/hash contract (`tools/largefile_service_qualification.sh:524–539`).

A bounded helper-level reproduction accepted the same one-byte file as `production`, `materialized`, `expansion`, and `edge`. This demonstrates missing role constraints; it is **not** a reproduction of the entire service/release gate passing. The milter exact-edge check independently enforces its stream boundary.

The required workload list at `tools/largefile_service_workload_check.py:116–141` also contains no fanotify/on-access case. These checks therefore cannot alone certify the fully allocated edge matrix and privileged on-access requirements in `PLAN.md:92–98`.

**Fix:** Enforce exact sizes of 34,359,738,368 and 34,359,738,369 bytes for the required edge cases. Capture and verify allocation evidence on the qualification filesystem, with a clear policy for sparse/compressed/reflinked files. Require complete valid-content controls separately from expected malformed/unsupported/limit outcomes. Add mandatory fanotify allow/deny and ingress-parity evidence, including denial on incomplete/resource/timeout/parser results. Require the full parser-family materialized matrix and PCRE memory-phase evidence, including RSS below 12 GiB before deep parsing, rather than inferring these from generic service success.

### 5. Multiple source trees and oversized status documents make evidence harder to follow

The `ClamAV` working folder is not the Git checkout and its summary still starts with an August 24 snapshot. The canonical `ClamAV-32gb` summary starts with September 4. The existing Docker container mounts `ClamAV` at `/src`, but its authoritative build points to a separate copied tree, `/tmp/clamav-authoritative-source`. Sampled current TNEF/ZIP/test source hashes matched that copied tree; the mount alone is not evidence that the latest tests used stale code.

The canonical “brief” summary has 1,560 lines, the detailed status has 2,829, and `audit1.md` has 24,417. Historical findings, current fixes, and outstanding release requirements are difficult to distinguish quickly. The recent stale-harness defects show why this matters operationally.

**Fix:** Use the canonical Git tree as the sole source of candidate snapshots. Record the complete source manifest and build configuration with every evidence bundle. Keep one short, generated current dashboard; move historical narrative to an archive without discarding evidence. Link each fixed acceptance milestone to its latest proof and unresolved dependencies. Track milestone closure independently of the growing fine-grained defect inventory.

## Recommended next milestones, in dependency order

| Milestone | Done means |
| --- | --- |
| Freeze a reproducible candidate | Canonical clean source snapshot; recorded source, compiler, dependency, configuration, and binary identities; coherent linked C/Rust/CTest and sanitizer baseline. |
| Make qualification enforce the contract | Capability-specific evidence requirements; role-specific exact-size/allocation checks; mandatory parser, PCRE-memory, fanotify, service, and production-database evidence. Synthetic rejection controls pass without counting as production proof. |
| Close remaining implementation limits | Required valid parser/signature paths complete above former local caps, with bounded memory/spools and exact late-marker checks; remaining required unsupported rows resolved without silently narrowing PLAN.md. |
| Qualify one complete vertical slice | On the certified runner, exercise one parser family through library, CLI, daemon and applicable clients with production CVDs, Release and sanitizer parity, materialized edges, cleanup, and measured resources. Record reusable infrastructure and that family's actual proof. |
| Complete the fixed acceptance matrix | Every remaining parser family and ingress, format-8 bytecode, full-subject PCRE, single-worker queue, milter, fanotify, and Sonic1 canary pass their required cases. All required rows have verified evidence. |
| Activate release defaults | Final readiness passes for the actual release candidate; only then activate and validate the release defaults and corresponding documentation. |

## Review validation and limits

- Read all five requested documents, concentrating on current snapshots, acceptance criteria, and the latest requirement audit; compared capability status histories and sampled implementation commits.
- `sh tools/largefile_release_readiness.sh --status`: correctly reports blocked with the counts above.
- `sh tools/largefile_release_readiness_test.sh`: passed. This validates existing gate controls, not completeness of their acceptance specification.
- Inspected the existing Docker container and compared SHA-256 for `tnef.c`, `others.c`, `unzip.c`, and `check_clamav.c` against the canonical checkout before focused test execution. This is sampled provenance, not a complete reproducible-build attestation.
- `sh tools/largefile_source_guards.sh`: passed, including the regenerated inventory/capability checks and embedded readiness controls.
- Existing ARM64 authoritative build: six focused `libclamav` CTest runs passed with `CK_RUN_CASE` set to `tnef`, `tnef_map`, `tnef_debug`, `zip`, `zip_sfx`, and `zip_map`. Command: `CK_RUN_CASE=<case> ctest -R '^libclamav$' --output-on-failure` from `/tmp/clamav-authoritative-build` in `clamav-poc-build`. No rebuild or installation was needed; these results remain focused development evidence.
- No current full x86-64 build, full sanitizer suite, production-CVD canary, 32 GiB materialized scan, or privileged fanotify run was performed in this review. Historical remote logs were not independently retrieved.
- No production code, workflow, or configuration was changed. No software was installed, no commit was created, and nothing was pushed or dispatched to GitHub.

The practical change in direction is to turn the growing collection of safety fixes into a fixed set of implemented and independently verified release capabilities. Keep the existing honest blocked status until those capabilities are actually demonstrated.
