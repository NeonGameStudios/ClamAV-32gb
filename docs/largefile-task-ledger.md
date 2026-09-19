# Large-file roadmap task ledger

Task ID: `R00` with the first bounded `R01` provenance slice

State: `development-verified` for the R00/R01/R02/R03/R04 specification and
development slices; certified release remains blocked.

## Starting identity

- Canonical source: `<repository-root>`
- Branch: `largefile-roadmap-qualification`
- Starting commit: `ff8905891b2b58a66c71859ab2c807cc4dee2dec`
- Starting worktree: dirty. Before this task, 10 tracked files were modified and 14
  roadmap/status/tooling files were untracked. Those changes were preserved as the
  candidate's pre-existing work.
- No immutable qualification candidate has been declared.
- Certified Linux x86-64 build/runner: not available in this macOS checkout; no
  runtime qualification is claimed.

## Total coverage assignment

The capability manifest is the row-level source of truth. Every current `(kind,id)` is
assigned by the following total routing rule; a new kind or an unmatched required row
must be triaged as `R00-TRIAGE` before implementation proceeds.

| Manifest rows | Assignment | Scope |
| ---: | --- | --- |
| 426 `library:*` except `path`, `fd`, and `fmap` | `R08-LIBRARY` | Reader/parser/library call paths and fail-closed behavior |
| 17 `matcher:*` | `R08-MATCHER` / `R09-REQUIRED-UNSUPPORTED` slice | Native matchers, bytecode, YARA, PCRE, fuzzy-image |
| 41 `feature:*` | `R08-FEATURE` | Build switches, optional feature behavior, and capability output |
| 80 `parser:*` | `R08-PARSER` / `R09-REQUIRED-UNSUPPORTED` slice | Every scanner dispatch branch and parser-specific cases |
| 23 ingress rows (`clamd`, `clamdscan`, `clamscan`, `milter`, `on-access`) | `R10-INGRESS` | Front-end parity, reports, queueing, cleanup, and on-access semantics |
| 3 `library:*` ingress rows (`path`, `fd`, `fmap`) | `R10-INGRESS` | Modern library ingress parity |
| 14 `unsupported:*` | `R09-ALLOWLIST-AUDIT` | Verify deliberate first-release exclusions remain precise |

The routing table covers the current 604 manifest rows: 426 `library` rows
other than `path`, `fd`, and `fmap`, 3 library ingress rows, 17 `matcher`, 41
`feature`, 80 `parser`, 23 front-end ingress, and 14 deliberate `unsupported`
rows. The recorded pre-R09 status was 0 qualified, 143 bounded, 433 pending,
and 21 unsupported. The current manifest keeps all seven required rows in
scope as pending: 0 qualified, 147 bounded, 443 pending, and 14 allowlisted
unsupported. Status labels do not qualify any row.

## Former required-unsupported escalation (`R09-REQUIRED-UNSUPPORTED`)

These seven rows are assigned to implementation or an explicit user scope decision;
they are not covered by the deliberate exclusion audit:

- `matcher:rust-fuzzy-image-ffi-admission`
- `matcher:fuzzy-image`
- `parser:CL_TYPE_AI_MODEL`
- `parser:CL_TYPE_IGNORED`
- `parser:CL_TYPE_PYTHON_COMPILED`
- `parser:CL_TYPE_RAR`
- `parser:CL_TYPE_RARSFX`

R09 moved these rows to `pending` after adding explicit fail-visible behavior
and focused development coverage. They remain release blockers until their
remaining parser/matcher implementation and capability-specific evidence are
complete; no unsupported exclusion was added.

## Completed bounded slices

R01 separated deterministic snapshot content from external Git provenance and
updated the Git-mode source manifest to include candidate untracked files while
excluding only its own output and the two generated metadata dashboards. The
snapshot no longer embeds `HEAD`, so a normal commit does not make the tracked
dashboard stale. `--provenance-output` records the source revision, input hashes,
snapshot hash, and readiness result as external JSON. Isolated temporary-Git
regressions cover generate → commit → freshness, generated-metadata exclusion,
and an untracked source file changing the manifest.

R02 now records the PLAN.md PCRE-phase (40 GiB) and post-PCRE (12 GiB) RSS
budgets in both runtime and service evidence while preserving the stricter
32 GiB overall workload bound. R13 real phase sampling remains required.

R04 now maps all 601 capabilities to named required cases and validates the
case-record schema. The service qualification path has an explicit,
fail-closed producer for directly mapped clamscan/clamd/clamdscan workloads,
and the runtime boundary path binds clamscan file/stdin detection reports to
its independent POC/oracle rows. The runtime path now also runs alert-disabled
32-GiB+1 file/stdin limit probes and binds their structured `LIMIT_INCOMPLETE`
records to the independent process/oracle rows, and it has matching exact-size
file/stdin clean-edge bindings backed by a benign database and `COMPLETE`
reports. The development capture now exercises clean, detection, and limit
edges for both file and stdin (six retained current-source records), and the
CLI normalizes stdin admission failures to exit 2 while preserving the exact
library status in the structured report. Both producers emit records before
their final checksum manifests;
service/runtime verifiers and authoritative readiness recompute retained-
artifact identities. The empty repository records file is intentionally
incomplete and cannot qualify a capability; no current-source Linux runtime
record exists yet. A separate direct-daemon development capture now retains 18
records across the six structured report protocols; its producer binds the
embedded scan outcome rather than the transport-success status and labels the
ARM64 Debug build as development. Daemon, library, parser, matcher, feature,
milter, fanotify, and full-size cases remain open for certified qualification.

R05 now independently validates the sparse boundary corpus before scanning and
again during evidence verification. The checker binds the exact eleven-row
manifest, logical sizes, marker windows, sparse allocation metadata, and
fixture stability without reading the 32-GiB holes. Four checker regressions
and the synthetic runtime-evidence regression pass. The deterministic stored-
ZIP late-member fixture now has an independent raw EOCD/central-directory/
local-header/CRC/marker oracle, with reproducibility, tamper, empty-archive,
and truncation regressions. The oversized FILDESREPORT control now has
fail-closed AlertExceedsMax-on/off mode bindings and a combined evidence
bundle; the qualification script restarts clamd between modes and restores
the certified on profile. This remains fixture/control evidence only; no live
current-source oversized service run is claimed.

R08 archive/Rust source audit found no new active ZIP, LHA/LZH, or ALZ defect to
patch: ZIP dispatches supported methods through fixed-window `unz_stream()` and
never reaches the retained contiguous legacy decoder; LHA/LZH and ALZ use
reader-backed paths with declared-range/output/CRC/limit checks and fail-visible
metadata narrowing. The call-path analysis is retained in
`docs/largefile-task-receipts/R08-archive-rust-audit.md`; runtime and
materialized-edge qualification remain open.

The follow-on R08 contiguous-read source audit found the roadmap-approved
whole-map PCRE read and two legacy PE unpacker reads for `PESpin` and `yC`.
The PCRE path is guarded by the effective PCRE limit, contiguous reservation,
deadline check, and post-match fmap release. The PE reads are preceded by the
shared `cli_pe_unpack_size_check`, which rejects buffers above the 1-GiB
individual-allocation ceiling and marks the recognized unpacker incomplete;
they cannot become unbounded 32-GiB parser allocations. The inspected parser,
decoder, hash, MIME, script, PDF, XAR, ZIP, and 7-Zip paths otherwise remain
windowed or spool-backed. Source guards passed for all 601 manifest entries,
so no parser source change was justified by this audit. Receipt:
`docs/largefile-task-receipts/R08-contiguous-source-audit-2026-09-13.md`.

After the retained Release tree disappeared, a fresh current-source ARM64
Release tree was configured with the application targets, built successfully,
and smoke-tested. The clean fixture returned `OK`/exit 0, the deterministic
HDB-backed ZIP returned `ClamAV-Test-File.UNOFFICIAL FOUND`/exit 1, and the
complete configured CTest suite passed 28/28 in 223.36 seconds. Receipt:
`docs/largefile-task-receipts/R03-current-source-release-smoke-2026-09-13.md`.
This remains development ARM64 evidence and does not change the certified
release boundary.

R09 formerly required-unsupported behavior is now development-verified.
Ignored-type classification no longer suppresses the generic raw matcher,
RAR/RARSFX backend failures remain explicit parse/incomplete results, the
focused Check group passes 5/5 and the backend-enabled static RAR regression
group passes 11/11, and the production-linked Rust fuzzy-image group passes
9/9. The legacy and modern scan callback fail-visible regressions are isolated
in an engine-backed Check case and pass 2/2. A rebuilt
`clamscan` also detects the repository logo through a temporary fuzzy-image
signature. A current-source ARM64 production CLI run now detects both decoded
repository RAR v2/v3 fixtures, and a neutral-prefix wrapper reaches the
RARSFX classifier at offset 128 and detects its nested member. The seven rows
are retained as pending in-scope work; no capability is promoted to certified
release status. A follow-on real CLI probe also binds Python bytecode, GGUF,
and ignored MP3 inputs to explicit `UNSUPPORTED`/`CL_EPARSE` reports with exit
2 and no false clean verdict. The receipt is retained in
`docs/largefile-task-receipts/R09-required-unsupported.md`.
The existing production clamscan regression now also exercises the newly
supported bounded Hamming-distance syntax: a one-bit-near image signature is
detected and a two-bit-near signature declared with distance one is rejected;
the focused CLI suite passes 4/4 against the freshly relinked development
scanner.
R04 now exposes a single `--require-r09` binding gate for both reviewed case
rows across all seven R09 capabilities; the authoritative repository record
file remains empty until retained current-source records are produced.

R09 real UnRAR backend probe (2026-09-12 UTC): the current-source ARM64
Release `clamscan` loaded the build-tree `libclamunrar_iface` module and
successfully extracted and scanned a valid stored RAR4 member and the same
member behind a neutral-prefix RAR-SFX wrapper. Both disposable SHA-256 HDB
scans returned `RarChild.UNOFFICIAL FOUND` with scanner exit 1; the RARSFX
trace classified `CL_TYPE_RARSFX` at offset 23 before nested extraction. The
source manifest is
`638480cc7d781d77029c9022aecd882c62b7cfd5d9737eb43c3d37dacaf7b0db`, the
scanner hash is
`b085b063e507da218d1ea5ed3436a91a7572bcf11462c4ec9ff3daa17eaa99c6`, and
the CMake cache hash is
`cf3622e210201cf7f5ce1ca92167de34585eb58353441f03d4ecbcf50cb5b3b7`.
This closes the optional-backend development probe but does not promote the
two parser rows: complete corpus, full-size, sanitizer, certified x86-64,
production-CVD/service, Sonic1, and final release evidence remain required.
Receipt: `docs/largefile-task-receipts/R09-real-unrar-backend-2026-09-12.md`.

The CMake unittest fallback was also made non-vacuous: explicit unittest
discovery now runs the `unit_tests/clamscan` directory when pytest is absent,
with a source guard pinning that command. The current-source ARM64 Release
aggregate exercised 127 clamscan cases and passed with one skip; the broader
14-test CTest subset and dedicated clamd suite also passed. Stale expectations
were reconciled with the roadmap's fail-visible ZIP/PE/CVD/PDF contracts, and
the CVD FIPS test now converts and signs the historical fixture through the
repository's existing test tooling. Exact evidence is in
`docs/largefile-task-receipts/R03-clamscan-aggregate-2026-09-12.md`.

The required `parser:CL_TYPE_IGNORED` path now has a production-linked CLI
regression as well as its direct-library cases. A minimal ID3/MP3 input is
recognized as ignored: without a matching raw signature it returns explicit
`Can't parse data`/exit 2, while the same recognized shape with an outer raw
signature returns `Ignored.Raw.UNOFFICIAL FOUND`/exit 1 and retains the
incomplete warning. Receipt:
`docs/largefile-task-receipts/R09-ignored-type-cli-2026-09-12.md`.

The same real-CLI contract is now covered for the recognized Python-compiled
and AI-model paths: malformed Python and ONNX inputs return parser-specific
incomplete results with exit 2, while exact outer raw markers return exit 1
detections. This keeps parser failure visible without allowing recognized
content to suppress malware matching. Receipt:
`docs/largefile-task-receipts/R09-parser-policy-cli-2026-09-12.md`.

The capability-record checker now binds each reviewed case suffix to an
allowed completion contract: clean and valid-complete cases must be complete,
detection and exact-tail cases must be detection-terminated, limit cases must
remain limit-incomplete, and fault/unsupported/rejection cases must remain
explicitly incomplete. This prevents a capability-specific record from being
made superficially plausible by pairing a named late-detection or failure case
with a contradictory clean result. The focused acceptance and producer tests,
full source guards, and release-readiness regression all pass; no capability
status was promoted.

Verified commands and results:

- `python3 -B tools/largefile_status_snapshot_test.py` — 12 tests passed.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — passed.
- `sh tools/largefile_source_guards.sh` — passed; 597 capability entries validated.
- `sh tools/largefile_service_evidence_check_test.sh` — passed.
- `python3 -B tools/largefile_acceptance_case_producer_test.py` — passed,
  including tampered-artifact rejection.
- `python3 -B tools/largefile_runtime_acceptance_case_producer_test.py` —
  passed, binding both runtime detection-edge records.
- `sh tools/largefile_runtime_evidence_check_test.sh` — passed.
- `python3 -B tools/largefile_acceptance_cases.py --check-map` — passed for 597 capabilities.
- `python3 -B tools/largefile_acceptance_cases.py --check-records` — schema passed with 0 records.
- Disposable static `libclamav_rust` CTest — 143 tests passed after the
  Rust test-seam fix; full CTest remains environment-limited on ARM64.
- `git diff --check` — passed.
- `sh tools/largefile_release_readiness.sh --status` — exit 1, expected `release_readiness=blocked`.

R10 development ingress now has current-source ARM64 smoke receipts for
`clamscan`, `clamd`, and `clamdscan`, including file, stream, and structured
report paths. A follow-on current-source daemon smoke covers file, stdin
stream, and fd-passed reports; all three return the exact alert line and
`DETECTION_TERMINATED` report with matching offset. The companion client
receipt binds `clamdscan --fdpass` and `clamdscan --stream` across clean,
detection, and MaxFileSize-limit outcomes, adding six records to the 18 direct
daemon records. During this verification a real client defect was fixed in
`common/clamdcom.c`: path report commands use `sendln()`, whose zero return is
success, but the shared report code had treated zero as failure and disconnected
before reading the daemon frame. A socketpair regression test covers that
contract across `CONTSCANREPORT`, `MULTISCANREPORT`, and
`ALLMATCHSCANREPORT`, and a fresh-daemon integration run reaches all three
path commands successfully. This remains development evidence only; it does
not create R04 acceptance records or replace the authorized Linux x86-64
qualification runner. The rebuilt `check_clamd` now supports filtered parser
and client groups (27/27 and 7/7), while a live current-source daemon passes
69/69 command checks and 4/4 concurrent stress checks under the legacy
envelope. Its intentional large-file admission refusal on ARM64 remains
explicit. The milter-enabled build also fixed a missing structured-report
declaration include in `clamfi.c`; the live development milter protocol harness
passes clean, infected, exact-limit, and limit-plus-one actions. The default
32-GiB milter profile remains reserved for the certified runner. The same
current-source build now includes the registered milter quota target, and CTest
passes both milter controls (2/2) under the explicit ARM64 legacy-limit
development profile. Structured-report clients now reject infected frames
without a nonempty `last_alert` instead of emitting a bare `FOUND` line; the
socketpair regression covers both the exact-name and malformed-report paths.
The fdpass client now preserves a client-side `CL_EMAXSIZE` refusal as a
populated `LIMIT_INCOMPLETE` report with root size, configured limits, and the
exact MaxFileSize reason. See
`docs/largefile-task-receipts/R10-clamdscan-client-development-2026-09-07.md`.
A follow-on audit also closes the daemon socket when structured serial report
processing fails before callback cleanup; the focused report/result/input
policy checks and the full source guards pass for this source change.
The next structured-ingress slice adds stream report preflight parity: a
known-size `StreamMaxLength` refusal now reaches the same populated
`LIMIT_INCOMPLETE` fallback as fd-pass, while direct stream callers retain
their historical soft-fail result. The current-source ARM64 pair was relinked
and the live report matrix passed clean, exact detection, and alerts-off path,
fd-pass, and stream limit cases with exit codes 0, 1, and 2 as appropriate.
The retained receipt is
`docs/largefile-task-receipts/R10-structured-daemon-ingress-2026-09-07.md`.
The registered socketpair regression was not run because the cached test
container lacks `check.h`; this remains development evidence only.
The follow-on IDSESSION slice found and fixed the parallel-client equivalent:
known-size stream and fd-pass refusals under `--multiscan --report-json` now
retain the input size, configured limits, exact reason, `LIMIT_INCOMPLETE`
completion, and exit 2 instead of a generic open/resource fallback. Both
multiscan modes passed against the current-source ARM64 pair. The retained
receipt is
`docs/largefile-task-receipts/R10-multiscan-limit-parity-2026-09-07.md`.
The follow-on outcome-parity check then exercised multiscan behavior across
path, stream, and fd-pass ingress (stream and fd-pass use the client IDSESSION
path; path uses the daemon MULTISCAN command). Clean controls returned exit 0
with `COMPLETE`; exact detection fixtures returned exit 1 with the expected
signature and offset in all three transports. The six-report matrix and
client-log checks passed, with development evidence retained in
`docs/largefile-task-receipts/R10-multiscan-outcome-parity-2026-09-07.md`.
The next bounded queue check started two streamed clients against a fresh
one-worker/two-queue daemon and a 64-MiB control fixture. Both returned clean
`COMPLETE` reports; daemon logs retained the pending/available INSTREAM
admission transitions and accepted queued dispatches. Timing/RSS was not
claimed because the cached image lacks the optional timing utility. Evidence
is retained in
`docs/largefile-task-receipts/R10-single-worker-queue-2026-09-07.md`.
The companion operational-failure matrix sent one missing target through path,
stream, and fd-pass multiscan forms. All three returned exit 2 with
`RESOURCE_FAILURE`/`Can't get file status`, zero scan-work counters, and no
false clean or detection result. The receipt is retained in
`docs/largefile-task-receipts/R10-operational-failure-parity-2026-09-07.md`.
The four changed on-access units were subsequently recompiled from the
worktree and linked into a fresh ARM64 `clamonacc` ELF against the existing
static development libraries; its configuration/help path passed, while the
unprivileged container correctly rejected `fanotify_init`. This does not
replace a coherent full-source CMake rebuild or certified evidence. A
privileged disposable run then initialized fanotify and completed the real
clamonacc-to-clamd ping handshake with `PONG` and exit code 0; permission-event
scanning and certified x86-64 evidence remain open. The same current-source
binary now also exits cleanly with status 2 when the container rejects its
fanotify mark, logging `ClamScanQueue: stopped` instead of hanging in queue
shutdown; this closes a cancellation/condition-variable lifecycle defect while
leaving the filesystem-specific permission-event limitation explicit.

R08 CVD archive finalization now has a current-source development receipt in
`docs/largefile-task-receipts/R08-cvd-tar-finalization-2026-09-06.md`. The
shared tar writer emits both required end-of-archive blocks for sigtool and
freshclam, unsigned `.info` loading ignores embedded DSIG metadata without
weakening signed verification, and the rebuilt sigtool cdiff/build tests pass.
The CVD header parser accepts valid fixed-width space padding, and positive
FreshClam full-download paths now generate and sign marker-complete fixtures
at test runtime while malformed fixtures remain rejection coverage. The direct
current-source `cl_suite` run passes 2,271/2,271, deterministic CTest passes
8/8, freshclam passes 11/11 with one platform skip, and clamd passes 15/15
under container-local socket testing. This remains development verification;
certified x86-64, sanitizer, full-size, production-CVD, daemon qualification,
and final release evidence remain open.

R03 development probing now has a coherent ARM64 build from the current
roadmap checkout. Inside disposable `clamav-largefile-local-toolchain2:latest`
containers, CMake 3.25.1/Clang 16.0.6/Rust 1.97.1 configured with JSON-C,
OpenSSL, zlib, PCRE2, milter, clamonacc and UnRAR enabled; the full Debug
application build reached 100% and linked the principal scanner, daemon,
client, milter, on-access, bytecode, signature and updater binaries. Version
and help smoke checks loaded the resulting binaries. The documented static
test configuration also linked, and the isolated Rust CTest passed all 143
tests after a narrow fix removed duplicate test-only C symbols from the Rust
static-test seam; the normal Rust target rebuilt successfully. The host
remains macOS/ARM64. A bundled `clamscan` fixture scan also returned the
expected `ClamAV-Test-File.UNOFFICIAL FOUND` result with exit code 1. Full
CTest was not promoted because the ARM64 container
hit a `check_clamav` runtime segfault, daemon socket/admission restrictions,
and dirty-inventory evidence. This is development verification only, not
certified Linux x86-64 Release, sanitizer, daemon, or full-size qualification
evidence. See `docs/largefile-task-receipts/R03-development-probe.md`.
The later disposable-runtime revalidation restored the temporary JSON-C and
Subunit runtime libraries without installing software: `libclamav` passed
2,666 checks, direct container-local daemon testing passed 15/15, and the
clamscan, freshclam, sigtool, admission, and report controls passed. The
CTest daemon wrapper remains a mount-backend limitation because its relative
socket is created under the host-mounted build directory. See
`docs/largefile-task-receipts/R03-disposable-runtime-revalidation-2026-09-07.md`.

## Next ready slices

1. `R03` qualification — locate the authorized Linux x86-64 runner and produce
   the required current-source Release/sanitizer build and retained identity
   evidence; the ARM64 development build is not a substitute.
2. `R04` integration — retain the six real ARM64 development capture records
   only as development evidence, then populate the required certified case
   matrix and extend explicit bindings to daemon, library, and full-size producers;
   authoritative readiness now consumes the mapping and requires records when
   evidence is promoted.
3. `R06/R07/R09` — continue the remaining modern OneNote, format-8 bytecode,
   and fuzzy-image work. R06 now has a vendored bounded-reader seam, but its
   parser-owned payload quotas and valid beyond-cap fixture remain open; the
   dependency audit and implementation receipt are recorded in
   `docs/largefile-task-receipts/R06-modern-onenote.md`. R07 is blocked by the
   absent compatible external format-8 compiler/artifact and authorized
   x86-64 execution runner; its repeated availability audit is recorded in
   `docs/largefile-task-receipts/R07-bytecode-format8.md`. R09's focused
   unsupported-path verification is recorded in
   `docs/largefile-task-receipts/R09-required-unsupported.md`; its seven rows
   remain pending until their remaining implementation or an explicit user
   scope decision is completed.
4. `R11–R14` — produce certified full-size, ingress, resource, on-access, and canary evidence.

The R13 on-access contract is now fail-closed: a qualified
`on-access:permission` record must carry revision-bound Linux fanotify
permission-event evidence covering clean allow, detection/limit/resource/
timeout/parser deny, a separate monitoring-only matrix, and recovery cleanup.
The verifier and release-gate control are development-tested only; no real
Linux fanotify run exists yet. The Linux event loop also now rebuilds its
`fd_set` for every `select()` wait so an idle period cannot silently drop the
fanotify descriptor from subsequent waits. Its read boundary now examines
`errno` only after a failed `read()`, preventing recovered read errors from
being applied to a later successful event batch. Queue startup and worker-pool
allocation failures are fail-visible, and an already-owned event is processed
inline if a worker-pool job cannot be allocated, preserving permission
responses and descriptor cleanup.

The follow-on R13 lifecycle slice now waits for the queue consumer and worker
pool to publish a ready state before `clamonacc` enters its event loop. Inotify
waits rebuild their descriptor set on every `select()`, extra-scan allocation
and queue-submission failures release owned data, DDD setup releases partial
tables and path lists, watch-table growth uses checked native sizing, and
normal shutdown joins both worker threads before freeing the shared context.
Fanotify event handling now preserves the original `readlink()` failure across
descriptor cleanup and fails visibly if context mapping cannot produce a valid
scan event. `tools/largefile_pcre_phase_evidence.py` now enforces the PCRE
subject/post-PCRE RSS phase contract with ordered
process-tree samples, exact-tail proof, runtime transition markers, and
revision-bound retained artifacts. See
`docs/largefile-task-receipts/R13-onaccess-lifecycle-pcre-phase-2026-09-07.md`.
The on-access file worker also zero-initializes its `STATBUF` before `stat()`;
a file that disappears between the kernel event and worker lookup now reaches
the fail-closed response path without passing an indeterminate structure by
value. The current-source ARM64 development relink and configuration/help
check were rerun; certified fanotify permission-event evidence remains
blocked by the unavailable authorized Linux x86-64 runner.
The same path-list parser now trims CR/LF safely, preserves a final line
without a newline, and returns an explicit read failure rather than accepting
a partial configuration.
The R10 stream-client ingress slice now allows callers without an option table
to use the shared bounded 32-GiB default; a registered socketpair regression
checks the resulting `zINSTREAM` framing, and a direct API smoke harness linked
against the refreshed common archive passes the same NULL-options contract. The
current `clamdcom.c` object and full source guards pass; the cached unit-test
container lacks the Check header, so no updated unit-test binary is claimed.
A separate coherent daemon/client smoke then rebuilt the current
`clamd/scanner.c`, `clamdscan/proto.c`, `common/clamdcom.c`, and
`libclamav/scan_report.c` objects, refreshed both static archives, and
relinked `clamd` plus `clamdscan`. With the existing service database and one
worker, ping returned `PONG`; path, stream, stream-multiscan, fdpass, and
multiscan detection each returned the exact expected alert and exit 1. The
retained development receipt is
`docs/largefile-task-receipts/R10-coherent-daemon-ingress-2026-09-07.md`.
This remains ARM64 development evidence and does not create R04 records.

The R09 fuzzy-image matcher now evaluates declared nonzero hamming distances
over the eight-byte image hash without allocating a candidate-result table;
over-width distances and extra signature fields fail closed. Runtime and
certified evidence remain required before changing the pending capability rows.

The five-issue roadmap-review follow-up was rerun from the canonical checkout.
The refreshed ARM64 binary passed the five-case R09 focused suite and the
dependency-free milter quota check; the acceptance-map, producer, fixture-
binding and snapshot controls also passed. The certified Linux x86-64 runner,
libmilter runtime, and reader-backed modern OneNote API remain unavailable, so
the follow-up records development verification only. See
`docs/largefile-task-receipts/R00-five-issue-followup-2026-09-07.md`.

The R04 evidence-binding slice now requires a standalone parser or matcher
acceptance record to retain an artifact whose SHA-256 is the exact scanned
fixture SHA-256. Runtime acceptance producers now retain their scanned input
artifacts, and the new rejection control catches a forged fixture digest.
Acceptance, runtime-producer, and full source-guard suites pass; this remains
development verification and does not promote any capability.

The R04 acceptance-record reader now validates exact TSV row widths before
constructing records. Rows with extra or missing fields fail closed instead of
being silently truncated or producing an indirect validation error. The R04
schema regression suite passes 9/9, including both malformed-width cases.

The same strict reader now backs the service and runtime acceptance producers'
workload/oracle tables. Their regression suites pass 4/4 and 5/5, including
malformed-row rejection, so producer inputs cannot silently discard evidence
columns before capability binding.

The status snapshot and PDF object-stream evidence checker now reject malformed
TSV widths and empty fields as well. The snapshot regression suite passes 13/13
and the focused PDF evidence-schema suite passes 4/4; the source-guarded
evidence tooling therefore shares the same fail-closed table-input rule.

The shared R04 TSV reader now also enables strict CSV parsing and converts
malformed quoting into a hard validation error. Its regression suite passes
10/10, while the acceptance producers and status snapshot tests remain green;
this closes another evidence-ingress ambiguity without creating qualification
records.

The same strict-parsing rule now covers the independent PDF object-stream,
sparse-boundary, and service workload/oracle readers. Their malformed-quoting
regressions pass alongside the existing width/empty-field controls: PDF 5/5,
boundary 5/5, and service workload 22 tests with 2 Linux-only skips. No
qualification record or capability status changed.

The follow-on R04 retention correction now also requires service-backed
acceptance records to list `provenance/service-inputs-before.json` among their
retained artifacts before using its fixture identity, and validates the
sidecar's versioned schema. The acceptance-case regression covers both the
rejection and retained-evidence paths. The local source guards pass; certified
qualification remains unchanged and blocked.

The R08 bytecode ownership slice fixed a real allocator-history crash in all
three buffer constructors. Newly grown slots are now fully zero-initialized
before the increased buffer count is published, so stale heap bytes cannot be
mistaken for an owned fmap lock. A deterministic `0xa5` regression covers the
memory, legacy file, and ABI-v2 file constructors while preserving a live
earlier lock. The rebuilt ARM64 development binary passes the bytecode suite
87/87 normally and with allocator perturbation, the complete C suite
2,834/2,834, and the C AddressSanitizer bytecode suite 87/87 with leak
detection. This is not Rust sanitizer or certified Linux x86-64 evidence, and
the capability remains pending. See
`docs/largefile-task-receipts/R08-bytecode-buffer-ownership-2026-09-07.md`.

No push, deployment, GitHub CMake workflow action, host software installation,
or production activity was performed. Disposable container package installs
and locked dependency downloads were used only to verify the ARM64 development
build.

The follow-on R08 full-sanitizer slice found a real failure-path stack read in
`emax_reached()`: an invalid recursion level was rejected by the public magic
scan entrypoint and then indexed while marking its parents non-cacheable. The
helper now clamps to the last real layer and walks the stack without signed
narrowing or unsigned underflow; the regression covers one-past and
`UINT32_MAX` levels with distinct current and parent maps. LeakSanitizer then
closed a Rust FFI error-object leak in alert-callback evidence removal, the
analogous evidence-add ownership path, and retained root evidence in five
direct parser tests that bypass public scan cleanup. The ARM64 static C
AddressSanitizer suite passes 2,788/2,788 with leak detection and no sanitizer
report, while the normal static UnRAR-enabled suite passes 2,834/2,834. This is
development evidence only; certified Linux x86-64 and R04 qualification remain
pending. See
`docs/largefile-task-receipts/R08-recursion-evidence-asan-2026-09-07.md`.

The R03 shared and mixed-sanitizer slice fixed three defects found by the
workflow-equivalent disposable x86-64 build: the private shared-library map
now exports `cli_scan_report_set_fallback_details()` for `clamdscan`, UDF
switch-table emission is deterministic when C and Rust address sanitizers are
combined, and bytecode global-array initialization uses alignment-safe
`memcpy` stores. The exact post-fix `libclamav` CTest target passed 1/1 in
308.12 seconds with ASan+UBSan and leak detection; the Rust target passed
152/152. Full 17-target CTest remained non-promoting because the container
has about 1.7 GiB rather than the required 48 GiB for daemon admission, and
two source-control tests exceeded their short CTest budgets under emulation.
Source guards, inventory synchronization, snapshot validation, and diff
checks pass. See
`docs/largefile-task-receipts/R03-sanitizer-shared-link-and-ub-2026-09-08.md`.

The R03 CTest harness follow-up raised only the timeout allowance for the two
deterministic source/evidence control tests, which can exceed one minute under
external storage or emulation. The regenerated workflow-equivalent sanitizer
configuration passed both targets 2/2: `largefile_source_guards` in 204.70
seconds and `largefile_runtime_evidence_check` in 114.46 seconds. No assertion,
release-gate, or qualification status changed.

A current local Docker capacity check confirms the remaining R03 boundary:
the container is `linux/x86_64` but exposes only `2467680 kB` of memory and
`3548892` KiB of free temporary overlay space, below the required 48-GiB
memory and 68-GiB disk thresholds. It cannot serve as the certified runner.

The follow-on PDF admission slice fixed two current-source defects found by
the new regression: the crypt-filter path now passes its validated `cf_len`
instead of an uninitialized local, and `pdf_getdict()` restores the opening
`<<` after token scanning has skipped delimiters and whitespace. The
null-context metadata and AES crypt-filter regressions pass in the rebuilt
ARM64 disposable binary's PDF case, 24/24 with zero failures and errors.
The source/evidence guard sweep, status freshness check, and diff check also
pass. A broader current-source `check_clamav` attempt was then killed with
exit 137 by the same approximately 2.4-GiB container after reaching the test
harness; no assertion or sanitizer diagnostic was emitted, so it is recorded
as a resource-limited non-result rather than a source failure. See
`docs/largefile-task-receipts/R08-pdf-metadata-callback-2026-09-08.md`.

The current-source production CLI was then relinked against the refreshed
static library. Its version smoke passed, and the repository's real
fuzzy-image CLI regression passed 4/4 in the disposable ARM64 container,
covering exact matches, disabled-feature behavior, malformed signatures, and
one-bit versus two-bit hamming-distance behavior. This strengthens R09
development evidence without promoting the fuzzy-image rows; certified,
full-size, sanitizer, and capability-bound records remain required. The
container-only full `check_clamav` attempt exited 137 under its approximately
2.4-GiB memory ceiling and remains a resource-limited non-result.

The independently filtered current-source Check groups then passed PDF 24/24,
required-unsupported 5/5, RAR 11/11, and the separate bytecode suite 87/87.
The earlier bytecode filter had selected no tests because bytecode is a
separate Check suite; that invocation was not counted as evidence.

The refreshed current-source ARM64 daemon/client pair then passed the
repository's three service smoke checks 3/3 in 2.109 seconds: daemon version,
PING/PONG, and clamdscan's daemon-version query. Startup reported the intended
32-GiB contiguous, 64-GiB temporary/logical-scan, and 256-GiB matcher-work
ceilings. This remains development evidence only; certified Linux x86-64,
full-size materialized, and R04 service records are still unavailable. See
`docs/largefile-task-receipts/R10-development-ingress.md`.

The same current-source pair then completed a fresh 24-record structured
service capture: all six daemon report commands plus fd-pass and stream client
transports across clean, detection, and MaxFileSize-limit outcomes. The matrix
was 8/8 `COMPLETE`, 8/8 `DETECTION_TERMINATED`, and 8/8 `LIMIT_INCOMPLETE`,
with exit codes 0/1/2 respectively. An independent acceptance-record
verification passed all 24 retained records and artifact bindings. This is
current ARM64 Debug development evidence only; it does not populate the empty
authoritative R04 records file. See
`docs/largefile-task-receipts/R10-development-ingress.md`.

The application-facing regression follow-up also passed the complete current-
source `clamd_test.py` target 15/15 in 31.470 seconds after moving its
temporary directory to container-local storage and supplying the disposable
container's missing `libsubunit.so.0`. The embedded `check_clamd` API suite
passed 107/107 and the final daemon PING returned `PONG`; the earlier CTest
failure was host-mounted socket setup, not a daemon source failure. The
companion `clamscan`, `freshclam`, and `sigtool` targets passed as well. This
is still ARM64 development evidence and does not qualify R04 records.

The CTest harness now supports `CLAMAV_TEST_TMP` as an explicit temporary-root
cache path. A fresh disposable ARM64 reconfiguration with
`CLAMAV_TEST_TMP=/tmp/clamav-ctest-temp` regenerated the environment with the
container-local path, and the registered `clamd` target passed 1/1 in 30.99
seconds. The target exercised the same 15/15 daemon suite and 107/107 embedded
API checks documented above. The default remains the unit-test build directory;
this portability fix does not change the release gate or qualify any R04 row.

The milter manual-wire boundary follow-up also passes from the current source.
Its mail-like fixture now disables mail parsing only for the raw exact-offset
oracle, so the temporary tail signature is detected at the root coordinate
instead of a child mail layer; the temporary signature matcher accepts the
`.UNOFFICIAL` suffix that ClamAV adds to ad hoc database names. The disposable
ARM64 run used a 4,096-byte development limit and passed with a 4,096-byte root,
4,096 logical bytes, exact offset 4,077, `DETECTION_TERMINATED`, zero skipped
operations, and milter reject. The ordinary four-case milter matrix was rerun
unchanged and passed `a`, `r`, `a`, `t`. This closes the local milter fixture
ambiguity without promoting ARM64 evidence or changing the certified 32-GiB
profile.

The R10 direct legacy-wire follow-up corrected a capability-binding defect in
the qualification tooling. Five edge labels had been recorded as direct
`clamd` SCAN-family/FILDES/INSTREAM workloads while the script actually called
`clamdscan` with structured-report options. They now use a dedicated probe for
the actual NUL-terminated `zCONTSCAN`, `zMULTISCAN`, `zALLMATCHSCAN`,
`zFILDES`, and `zINSTREAM` commands. The verifier types these rows as
`legacy`, checks clean/detection/size-limit text replies, and refuses a
structured report. Because the legacy protocol does not carry structured
counters or a native alert offset, the acceptance producer intentionally does
not promote these rows into R04 records. The disposable ARM64 daemon probe
passed all six detection commands, clean SCAN, and INSTREAM size-limit
behavior; the focused protocol suite passed 6/6 and the service/runtime
evidence regressions passed. This is development evidence only.

A follow-on verifier audit found that legacy workload rows checked their
protocol text and input identity but did not independently bind the recorded
process exit to the role oracle. The service workload verifier now performs
that exact status check, with a regression for a valid detection reply paired
with exit 0. The workload suite passes 24/24 and the full source-guard sweep
passes; no capability status or qualification claim changed.

The current-source ARM64 `clamscan` target was also rebuilt in a disposable
container after supplying only its missing development headers inside that
container. The rebuild completed at low concurrency, the scanner version
smoke passed, and `logo.png` returned `OK`; the temporary container was
removed. This strengthens executable development verification but remains
ARM64-only and does not create certified R03/R04 evidence.

The R10 service qualification startup probe was corrected after tracing the
client semantics: `clamdscan --ping ... --wait` continues into the ordinary
scan path after PING and may scan `$PWD` when no input is supplied. The
qualification loop now calls ping-only mode, with source guards rejecting the
regressed option combination. Shell syntax and the full source-guard sweep
pass. This closes a local qualification-tooling defect but does not promote
development evidence or alter the blocked release gate.

The R13 fanotify loop now fails closed when a permission event cannot be
queued or cannot be prepared: allocation, context mapping, metadata-copy,
metadata-version, read-link, and queue-admission failures send `FAN_DENY`
before closing the kernel event descriptor. Permission queue failures are not
retried after the decision is written; non-permission queue retry behavior is
preserved. The current-source `clamonacc` target compiled and linked in a
disposable ARM64 container, and the source guards now pin the denial helper.
No real permission-event claim was made; Linux x86-64 fanotify evidence is
still required.

The same R13 worker now treats an interrupted or short normal permission
response as an error, retries `EINTR`, and routes an unaccepted response
through the shared denial-and-close recovery path so an intended allow cannot
become an implicit allow during cleanup. It also rejects malformed queued
fanotify context before dereferencing its metadata descriptor. These changes
are source/build verified only; the authorized Linux x86-64 kernel run remains
required.

The shared fanotify fallback denial helper now retries `EINTR` before closing
an unqueued or otherwise failed permission event, keeping every local response
path consistent about complete kernel decisions. This remains development
source/build evidence; real Linux permission-event qualification is still
required.

The response-boundary validation also now releases a valid metadata descriptor
when the queued fanotify channel itself is invalid, preventing the new guard
from introducing a cleanup leak. Source/build verification remains
development-only until the authorized Linux kernel run is available.

The follow-on R08 current-source parser-family sweep ran 92 bounded Check
groups separately against the refreshed ARM64 development binary: Rust
LHA/ALZ, archive and filesystem containers, executable/image/document families,
mail/compression/OLE/VBA, SWF, and Mach-O. All 554 checks passed with zero
failures or errors. No new implementation defect was exposed; the sweep is
recorded in `docs/largefile-task-receipts/R08-current-source-parser-sweep-2026-09-08.md`.
It remains development evidence only and does not replace the certified
x86-64, full-size, sanitizer, resource, fanotify, or R04 qualification runs.

The follow-on public ALZ/LHA integration run exposed and fixed a real current-
source defect: ALZ extraction discarded the available member prefix on a
decompressed-size limit or malformed declared-size/CRC/trailing-data result,
so nested signatures in that prefix were missed. `ExtractSink::finish_partial()`
now scans available bounded output before preserving the limit or parser error;
hard backing-store, timeout, sink, allocation, and stop failures still abort.
The rebuilt ARM64 development scanner passes the public ALZ/LHA suite 13/13,
the Rust CTest target 152/152, and focused `rust_alz` C checks 2/2. The source
guards and current snapshot freshness check pass after regenerating the
line-numbered inventory. See
`docs/largefile-task-receipts/R08-alz-partial-prefix-scan-2026-09-08.md`.
This remains development evidence only; the certified x86-64/full-size gate
is still blocked.

The follow-on R04 service acceptance-producer correction now admits mapped
workload report and log paths before opening either file, and rejects
unsupported workload kinds and malformed offset-check fields at that same
boundary, and the producer now rejects unknown workload labels instead of
silently dropping them. The shared acceptance validator, service workload verifier, runtime
acceptance producer, and PDF evidence checker now also reject symlink
components before resolving retained paths. This closes a local
evidence-tooling read-before-validation and link-following gap; the acceptance
schema suite passes 11/11, the PDF schema suite 6/6, the runtime producer
6/6, the service/result checker 35/35 with two Linux-only filesystem tests
skipped on this host, and the complete source-guard sweep passes. No
capability status changed and the authoritative acceptance-record file
remains empty pending certified evidence.

The service workload/oracle reader now rejects wrong-width rows and empty
fields at TSV ingestion, before later indexing or evidence access. New
regressions cover both malformed forms; the service workload suite passes
27 tests with two Linux-only filesystem tests skipped on this host, and the
complete source-guard sweep passes. No capability status changed and the
authoritative acceptance-record file remains empty pending certified evidence.

The R10 health probe now validates the daemon's exact NUL-terminated `PONG`
reply after `zPING`; a successful socket write alone no longer reports a
healthy service. The focused source change is recorded in
`docs/largefile-task-receipts/R10-development-ingress.md`. A fresh executable
was not claimed because the cached ARM64 container lacks the generated OpenSSL
development header needed by the dependent relink; certified x86-64 health
evidence remains open.

The on-access client now applies the same exact NUL-terminated `PONG`
validation to both its remote-detection and retrying health paths. Wrong,
truncated, or absent daemon replies cannot produce a false healthy result.
Source/evidence guards pass; the cached ARM64 image lacks the libcurl
development header needed to relink the on-access target, so no new executable
or runtime qualification is claimed. Certified privileged Linux x86-64
evidence remains open.

The on-access transport now retries `EINTR` correctly when `onas_sendln()`
returns a zero-byte send; its previous `sent && errno == EINTR` test could
never enter the retry branch. This is source/control verified only because the
cached image still lacks the libcurl development header for a fresh object
build.

The on-access stream preflight now rewinds descriptor 0 when it refers to a
regular file; the former special case could omit the file prefix. This remains
source/control verified because the disposable image lacks libcurl development
headers for a fresh on-access object.

The excluded-file fanotify permission path now retries `EINTR` while delivering
`FAN_ALLOW` and sends `FAN_DENY`/closes on short or failed delivery. This keeps
the response boundary fail-closed without turning a transient interruption into
an avoidable denial; privileged Linux x86-64 evidence remains open.

On-access `FILDESREPORT` descriptor passing now retries `EINTR` and requires
`sendmsg()` to deliver its complete one-byte payload, so ancillary FD delivery
cannot be reported successful after a short send. Fresh object/runtime evidence
remains blocked by the disposable image's missing development headers.

Shared legacy `FILDES` and `FILDESREPORT` descriptor passing now applies the
same boundary check: it retries `EINTR` and requires `sendmsg()` to deliver the
complete one-byte payload before returning success. This protects clamdscan's
shared client path and other legacy callers from treating a short ancillary
send as delivered. The source guard and local control suite pass; fresh
object/runtime evidence remains blocked by the disposable image's missing
development headers.

Shared legacy stream preflight now inspects descriptor 0 as well as every
other descriptor, and rewinds regular files before sending `zINSTREAM` or its
report variant. The former `0 != fd` guard could skip both checks when standard
input referred to a regular file, allowing a suffix-only or over-limit stream.
Source controls remain green; no fresh shared-client binary or certified
runtime evidence was claimed.

Fresh current-source object verification succeeded in a disposable ARM64
container after installing the missing development packages inside that
container: `clamonacc/client/protocol.c.o` and `common/clamdcom.c.o` both
compiled from the canonical checkout. The complete `clamonacc` link was not
claimed because Cargo attempted to refresh unavailable Git dependencies; this
is object-level development evidence, not certified x86-64 runtime evidence.

After adding Git to the disposable container, the complete current-source
`clamonacc` target built and linked at 100% with Clang 16.0.6 and Rust 1.97.1,
with UnRAR, Milter, fanotify, and shared libclamav enabled. The resulting
ARM64 development hashes are `b1fdaa8d73a29668c097577fd9ec163fa0d221e45aa519e96e7340ede109d8ef`
(`clamonacc`), `a656c48e7ecb857291ea96fde13a08c1fa6c6b636e50a1cadece493ec8d1dfda`
(`libclamav.so.14.0.0`), and
`eaa517a32169a0c02f176802cddf65ca5157f34a392b0ba78a14776207db930c`
(`libcommon.a`). With `-c /dev/null`, the freshly linked `clamonacc --help`
exited 0 and reported `1.5.3-largefile-devel`. This remains ARM64 development
evidence, not certified x86-64 or full-size qualification evidence.

The rebuilt `check_clamd` client stream-accounting group passed 10/10 in the
disposable ARM64 container. It includes the new descriptor-0 regular-file
regression, which starts from a nonzero offset and verifies that the shared
`zINSTREAM` sender rewinds and transmits the complete payload, alongside the
existing over-limit and descriptor-error checks. This remains focused
development evidence rather than certified x86-64/full-size qualification.

Shared `sendln()` now retries `send()` when the interrupted call returns
`-1`/`EINTR`; the prior positive-result condition could report a transient
signal as a transport failure. A deterministic socketpair regression fills
the sender, interrupts the blocked send, drains the peer, and verifies the
payload. The rebuilt client stream-accounting group passed 11/11 in the
disposable ARM64 container. This remains development evidence rather than
certified x86-64/full-size qualification.

The R04 acceptance validator now binds the generic `complete` case suffix to
the `COMPLETE` outcome. Previously, generic library/matcher/feature cases
could carry a contradictory detection or failure while retaining the
`complete` case ID. The new end-to-end negative regression and focused R04
schema suite pass 11/11, and the full source/evidence guard sweep passes.
No qualification record or capability status changed.

The R04 completion-contract table is now total for all generated case
suffixes: generic `complete`, feature `enabled`, and R09
`required-behavior` are explicitly bound, while an unknown suffix is
rejected fail-closed. The focused schema suite passes 12/12, including a
generated-suffix coverage regression, and the full source/evidence guard
sweep passes. No qualification record or capability status changed.

The current-source ARM64 development build was repaired inside a disposable
container and rebuilt from the canonical checkout for the application-facing
targets `clamscan`, `clamd`, `clamdscan`, and `check_clamd`. The clean CLI
control returned `OK`, the repository test signature returned the exact
`ClamAV-Test-File.UNOFFICIAL FOUND`, and the full `clamd_test.TC` integration
target passed 15/15 in 29.529 seconds; its focused `check_clamd` path reported
111 checks with zero failures or errors. This closes the local R10 daemon
rebuild/integration slice without changing capability status. The aggregate
`check_clamav` target remains unavailable in this shared-library build shape
because its wrapper-only test declarations are enabled only for the static
Linux test configuration. The receipt is retained in
`docs/largefile-task-receipts/R10-current-source-daemon-rebuild-2026-09-08.md`.
This remains ARM64 development evidence; certified x86-64 Release/sanitizer,
full-size, fanotify, and production-canary evidence remain open.

The current-source static aggregate test executable was rebuilt from the
canonical checkout in a disposable ARM64 container with static libclamav and
the test wrappers enabled. With `T=120`, `CK_DEFAULT_TIMEOUT=120`, and
`CK_FORK=yes`, the focused `cl_scan_api` group passed 836/836 checks, the
focused MHTML group passed 5/5 checks, and the full aggregate suite passed
2,836/2,836 checks with zero failures and zero errors. The initial default
timeout run only reported slow 64–65 MiB streaming cases; rerunning them with
the explicit development budget completed cleanly. Artifact hashes and the
exact environment are recorded in
`docs/largefile-task-receipts/R03-static-aggregate-check-2026-09-08.md`.
This remains ARM64 development evidence; certified x86-64 Release/sanitizer,
full-size, fanotify, and production-canary evidence remain open.

The requested remote SSH Sonic3 runner was rechecked with the supplied
`sonic3-sudo` profile. Profile/capability description succeeded, but the live
connection diagnostic was denied by `no_matching_allow_rule`; the normal
read-only `uname -a` command matched the configured full-access rule and then
timed out during SSH connect after 30 seconds with no remote command started.
Sonic1 was not guessed because no Sonic1 login-profile name was supplied.
This is retained as R03 runner evidence in
`docs/largefile-task-receipts/R03-sonic3-connection-2026-09-08.md` and leaves
certified x86-64 qualification blocked without changing local capability
status.

Final local control revalidation (2026-09-08): `sh
tools/largefile_source_guards.sh` returned exit 0 from the canonical checkout.
The service-evidence control script also passed its 27 input-policy tests
(with two expected Linux-only skips), 10 result checks, and 22 oversize
checks. The current snapshot and `git diff --check` remain clean. These are
development/evidence-integrity controls only; no capability status changed and
the certified runner, full-size, privileged fanotify, and production-canary
gates remain open.

R03 development sanitizer slice completed on Sonic1 (2026-09-09): a fresh
isolated C ASan/UBSan build from the repaired source graph linked `clamscan`,
`clamd`, and `clamdscan` successfully with the direct offline Rust toolchain.
Named clean and detection smoke containers exited 0 and 1 respectively with
the expected OK/detection results and no ASan/UBSan diagnostics. The artifact
hashes and exact container/build paths are recorded in
`docs/largefile-task-receipts/R03-sonic1-current-source-gate-2026-09-08.md`.
This remains development evidence only because the complete current test
source and frozen certified source graph are still unavailable on the remote
runner; no capability status changed.

The Sonic1 Rust sanitizer prerequisite was checked explicitly: the retained
image has stable rustc 1.97.1, and an isolated `-Zsanitizer=address` configure
attempt failed at the repository's nightly-toolchain guard. No toolchain was
installed or downloaded. R03 now has C ASan/UBSan development evidence, while
the required Rust address-instrumented artifact remains blocked on an
authorized nightly Rust environment; no capability status changed.

The C sanitizer evidence was extended through the daemon/client path on
Sonic1: sanitizer `clamd` stayed healthy, `clamdscan` returned clean 0/OK and
large-file detection 1 with the exact alert, `--ping=1` returned PONG, and
retained structured reports bound the results. The report hashes and service
container identity are recorded in
`docs/largefile-task-receipts/R03-sonic1-current-source-gate-2026-09-08.md`.
This remains development evidence only; the required Rust address-instrumented
artifact is still blocked on an authorized nightly toolchain and no capability
status changed.

R10 harness parity correction (2026-09-09): the service qualification matrix
now requires separate report-backed `clamdscan` workloads for plain
`--multiscan`, `--stream --multiscan`, and `--fdpass --multiscan`, alongside
the existing direct legacy-wire `MULTISCAN` probe. The verifier, synthetic
evidence control, and focused tests all require the three labels. This closes
an omission in the acceptance harness; no capability status changed.

The sanitizer service slice also covered framed `clamdscan --stream` ingress:
clean exited 0/OK and the marker exited 1 with the exact large-file alert.
Retained stream-report hashes and the stopped named service container are
recorded in the R03 receipt; no capability status changed.

The same sanitizer service slice covered Unix-socket fd passing: clean
`clamdscan --fdpass` exited 0/OK and the marker input exited 1 with the exact
large-file alert. The retained report hashes and stopped named container are
recorded in the R03 receipt; no capability status changed.

The existing Sonic1 C ASan/UBSan build was also given a bounded CTest source
graph probe. `largefile_poc_fail_closed` and
`largefile_runtime_evidence_check` passed. The source-guard entry failed on
the repaired copy's stale `common/clamdcom.c`, while the acceptance-schema,
clamscan-admission, and clamd-report-protocol entries could not start because
their current test files were absent; CTest reported 2/6 passed and exit 8.
This is retained as an exact partial-graph prerequisite in
`docs/largefile-task-receipts/R03-sonic1-current-source-gate-2026-09-08.md`.
The next Sonic1 run requires the complete current source/test graph and a
regenerated build; no capability status changed.

The Sonic1 sanitizer service slice also covered `clamdscan --multiscan
--stream`: clean returned 0/OK and the marker input returned 1 with the exact
large-file alert; the structured reports bind complete/detection outcomes and
offset `1048512`. A plain `--multiscan` client-only path correctly failed
closed when the daemon could not stat the unmounted client path. Report hashes
and the stopped named daemon are retained in the R03 and R10 receipts. This is
development evidence only; no capability status changed.

The Sonic1 sanitizer service slice then verified plain `clamdscan
--multiscan` path ingress with shared fixture paths: clean returned 0/OK and
detection returned 1 with the exact alert and offset `1048512`. The reports
and stopped named daemon are retained in the R03/R10 receipts. No capability
status changed.

The Sonic1 sanitizer service slice then verified `clamdscan --fdpass
--multiscan` after repairing permissions on a disposable socket volume. Clean
returned 0/OK and detection returned 1 with the exact alert and offset
`1048512`; the successful daemon log had no sanitizer diagnostic. The initial
startup-abort probe exposed a 2,313-byte LeakSanitizer engine-init leak, so
`clamd/clamd.c` now frees the engine on pre-`recvloop()` startup failure and
clears ownership after `recvloop()` returns. The remote binary predates that
source fix, so post-fix sanitizer verification remains open; no capability
status changed.

Current-source Sonic1 rebuild boundary (2026-09-09): CMake configure completed
on a disposable development overlay, and the current `clamd/clamd.c` plus
`common/clamdcom.c` translation units compiled cleanly with the generated
project flags. The full Rust-linked build remains blocked by missing locked
Cargo crates (`adler2 v2.0.1`, then `android_system_properties v0.1.5` in
offline checks) after one bounded fetch attempt timed out. No capability status
changed; certified/current-source full-build and qualification evidence remain
open.

The same Sonic1 C-only check also compiled the current `clamdscan/client.c`
with generated flags, covering the client-side default, fdpass, stream, and
multiscan selection paths. No capability status changed.

The Docker-contained ARM64 development service producer then generated 24
artifact-bound R04 records across the six structured daemon REPORT commands
and `clamdscan` fdpass/stream, with clean, detection, and limit outcomes for
each. The generic verifier accepted all 24 records against their retained
fixture, oracle, database, report, log, build, and source identities. Evidence
is retained at `/private/tmp/clamav-r04-service-capture-20260909`; it remains
development-only and no capability status changed.

R06 bounded-reader follow-up (2026-09-09): added a short-read regression for
the legacy OneNote `Read + Seek` path, limiting every source read to three
bytes and confirming complete attachment output without abort. The pinned
modern parser still exposes only an `&[u8]` reader, so the modern >256 MiB
path remains blocked pending a reviewed dependency API or bounded parser fork;
no capability status changed.

The cached Sonic1 OneNote module was also compiled directly with existing Rust
artifacts and ran 13/13 existing module tests successfully. This does not claim
the newly added local short-read test was run remotely, and does not change the
modern-parser dependency blocker or capability status.

Targeted Sonic1 relink follow-up (2026-09-09): the retained current-source
volume's `clamd` target reached the C graph after a root-owned-volume retry and
after mounting the existing generated `clamav_rust.h` (SHA-256
`fa88017207eea3dea79edf0523911139c6f5aa0a8b759ec254225a0e0db20739`). The
build then failed at the older remote `libclamav/fmap.c` versus current
`clamav.h` declaration boundary. The canonical checkout is internally
consistent; the remote overlay is incomplete and must be replaced by a
complete source transfer before a full current-source relink can be claimed.
No capability status changed.

Development service lifecycle follow-up (2026-09-09): strengthened the local
ARM64 development producer so each outcome group records daemon health before
and after cases plus verified stop cleanup, binds the lifecycle artifact into
each record, and fails closed on health or cleanup failure. The focused
lifecycle test passed 4/4 and the full local tools suite passed 144 tests with
2 expected skips. This is development-only evidence; no capability status
changed.

Release-service lifecycle follow-up (2026-09-09): added a generation-tagged
service lifecycle artifact to the qualification runner and made the independent
evidence verifier require exact startup/pre-stop PONG plus process, socket, and
PID-file cleanup for every daemon generation; its path and SHA-256 are bound
into the service build identity. The synthetic runtime evidence regression
passed and the shell/source guards passed. No real release run or capability
promotion was claimed because the coherent current-source build remains
blocked.

Development capture lifecycle follow-up (2026-09-09): removed the harness
cleanup that could delete a stale Unix socket before recording its state. The
producer now requires a regular PID file before readiness, retains observed
socket and PID-file absence after stop, and binds both results into the
lifecycle artifact. Acceptance fixtures, source guards, and the full local
tools suite passed (145 tests, 2 expected skips); the retained 24-record bundle
predates this producer change and was not relabelled.

Sonic1 provenance recheck (2026-09-09): the existing container that completed
`clamd` and `clamdscan` is bound to the repaired 2026-09-08 source snapshot,
not the canonical current checkout. The separate current-source volume has a
broad dirty transfer state with deleted files and untracked AppleDouble
artifacts, so it cannot support a coherent current-source release claim. No
new build or private-source transfer was attempted; the build/dependency gate
remains open.

Current-source Docker application build (2026-09-09): the canonical checkout
was mounted read-only into a disposable Linux x86-64 `rust:1.97-bookworm`
container and configured coherently for Release shared/static libraries,
applications, tests, milter, clamonacc, UnRAR, and interpreter bytecode. The
full CMake build reached `100% Built target check_clamav`, and the complete
serial CTest suite passed `16/16`, including Rust, clamd/`check_clamd`, milter,
R04 capture, source guards, runtime evidence, and large-file controls. The
local tools suite also passed 145 tests with 2 expected skips. This closes the
current-source compile and development application-test slice for R03/R10;
it does not promote any R04 capability because the container has about 1.77
GiB available versus the 48-GiB exact-edge admission requirement, and it is
not a sanitizer or full-size qualification run. The current R06 modern-reader
dependency blocker and all seven R09 required-unsupported rows remain open.
Receipt: `docs/largefile-task-receipts/R03-current-source-docker-build-2026-09-09.md`.

Current-source sanitizer slice (2026-09-09): built the canonical checkout's
C scanner and daemon targets with explicit C/C++ AddressSanitizer and
UndefinedBehaviorSanitizer flags in a disposable Linux x86-64 container. The
instrumented scanner detected the generated HDB test signature, the daemon
protocol/lifecycle suite passed 15/15 cases in 50.01 seconds, and the native
Check run passed all 2,836 checks through CTest in 459.23 seconds. No
ASan/UBSan diagnostic appeared. This is a clean current-source C application
sanitizer slice, but not the nightly Rust sanitizer candidate and not 32-GiB
qualification. Receipt:
`docs/largefile-task-receipts/R03-current-source-sanitizer-2026-09-09.md`.

R09 bounded fuzzy-image reader slice (2026-09-09): replaced the scanner's
whole-input fuzzy-image admission with a Rust `FMapReader`/`BufReader` path,
bounded decoder working-set reservation, typed reader/status propagation, and
panic-safe reservation release. The sanitizer-linked GIF group passed 16/16,
including a valid 2-MiB encoded image under a 1.5-MiB contiguous cap; source
guards, the 145-test tools suite, and acceptance checks passed. This remains
development evidence only: the two required R09 matcher rows remain pending
for certified 48-GiB qualification. Receipt:
`docs/largefile-task-receipts/R09-fuzzy-image-reader-2026-09-09.md`.

R06/R03 current-source reader and sanitizer follow-up (2026-09-09): vendored
the pinned OneNote parser revision and added a bounded sequential reader with
short-read handling, typed resource/allocation failures, and bounded payload
materialization. Parser tests passed 13/13 unit and 4/4 integration cases;
the current-source x86-64 relink and focused `rust_onenote` run passed 2/2.
The mixed C/Rust sanitizer CTest bridge now supplies sanitizer runtimes only
to Rust test executables; focused Rust sanitizer CTest passed 1/1. Quota,
clamscan, clamd, freshclam, sigtool, MBR, and MHTML controls passed. The broad
configured CTest run remains non-green because the unfiltered C suite and two
repo-wide controls exceeded disposable-container time limits; certified
runner, full-size evidence, and capability qualification remain blocked.

R06 aggregate parser-memory refinement (2026-09-09): the vendored OneNote
reader now tracks cumulative parser-owned payload materialization under an
explicit 256 MiB budget and uses fallible reservations for both slice and
stream inputs. The parser suite passed 14/14 unit and 4/4 integration cases;
the full `libclamav_rust` consumer passed `cargo check --locked`; the outer
admission cap and certified full-size/late-content qualification remain open.

The generated large-file inventory was refreshed after the reader/build-script
line shifts, and the complete `tools/largefile_source_guards.sh` sweep passed
again across all 597 capabilities and acceptance controls.

Remote qualification retry and CTest allowance follow-up (2026-09-09): MCP-
SSH described the supplied `sonic3-sudo` profile for `sonic3`, but all three
read-only probes timed out during SSH connect before a remote command started;
the connection diagnostic was policy-denied. The previously requested
`sonic1` retry was policy-denied because that host does not allow the supplied
profile. No remote transfer or Docker test ran. Locally, the configured CTest
allowance for `largefile_development_acceptance_capture` was aligned with the
existing 300-second source/runtime control allowance after the standalone
capture passed near its former 60-second limit. The source/evidence guard
sweep passed across all 597 capabilities; no status changed. Receipt:
`docs/largefile-task-receipts/R03-r10-remote SSH-and-ctest-2026-09-09.md`.

R06 bounded stream-window refinement (2026-09-09): the vendored OneNote
reader now rejects oversized stream `read`/`peek` requests before internal
buffer growth and uses fallible refill reservations, preserving typed
resource/allocation failures. The focused source-level change is covered by
the reader regression; source guards, inventory freshness, and `git diff
--check` pass. The fresh parser run passed 15 unit, 4 integration, and 1
ignored doctest. A native C relink was not claimed because the available
disposable image lacks the required Check headers. The modern outer admission
cap and full per-object parser quota work remain open. No host installation,
remote execution, usage reset, commit, push, or workflow action was used.

R06 count-driven collection safety refinement (2026-09-09): the vendored
reader now enforces a typed 64 MiB collection budget with fallible incremental
reservation for compact ID arrays, object-property streams, property sets,
nested property-value sets, and the FSSHTTP end-marker/package collections.
The focused parser run passed 17 unit, 4 integration, and 1 ignored doctest,
including the nested property-values oversized-count regression. Source
guards, inventory freshness, snapshot validation, and `git diff --check` passed
across all 597 capability entries. A fresh full consumer check was attempted
but Docker Desktop failed to start after disposable build-disk pressure, so no
consumer result is claimed for this slice; the prior successful consumer check
remains recorded above. No host installation, remote execution, usage reset,
commit, push, or workflow action was used.

R06 ink-path decoder safety refinement (2026-09-09): the OneNote multi-byte
ink decoder now applies the typed collection budget and fallible reservation
before creating decoded value vectors, and reports truncated, over-wide, or
out-of-range varints as parser errors instead of panicking. The focused parser
run passed 20 unit, 4 integration, and 1 ignored doctest, including valid-zero,
truncated-length, and truncated-varint regressions. Source guards, inventory
freshness, snapshot validation, and `git diff --check` passed. Docker remained
unavailable for a fresh consumer-level compile, so no consumer result is
claimed for this slice. No host installation, remote execution, usage reset,
commit, push, or workflow action was used.

R06 post-reader mapping-table safety refinement (2026-09-09): the OneNote
mapping-table builder now returns typed parser results and bounds its
object/object-space maps and per-ID vectors with fallible incremental
reservations under the 64 MiB collection budget. The focused parser run passed
20 unit, 4 integration, and 1 ignored doctest. Source guards, inventory
freshness, snapshot validation, and `git diff --check` passed. Docker remained
unavailable for a fresh consumer-level compile, so no consumer result is
claimed for this slice. No host installation, remote execution, usage reset,
commit, push, or workflow action was used.

R06 legacy whole-file read safety refinement (2026-09-09): path-based OneNote
parsing now validates metadata against the materialization ceiling and reads in
bounded chunks with fallible reservations and a second limit check for files
that grow after metadata inspection. The focused parser suite remains at 20
unit, 4 integration, and 1 ignored doctest; source guards, inventory freshness,
snapshot validation, and `git diff --check` pass. Docker remains unavailable
for a fresh consumer-level compile, so no consumer result is claimed. No host
installation, remote execution, usage reset, commit, push, or workflow action
was used.

R06 derived property-vector safety refinement (2026-09-09): byte-property
copies now reserve fallibly, while `u16` and `u32` conversions enforce the
typed 64 MiB collection budget before pushing decoded values. The focused
parser suite passed 21 unit, 4 integration, and 1 ignored doctest, including an
over-budget derived-vector regression. Source guards, inventory freshness,
snapshot validation, and `git diff --check` pass. Docker remains unavailable
for a fresh consumer-level compile, so no consumer result is claimed. No host
installation, remote execution, usage reset, commit, push, or workflow action
was used.

R06 modern scanner admission lift (2026-09-09): removed the stale production
`FMap::WHOLE_INPUT_MAX` refusal from the modern OneNote scanner so logical
inputs above the former cap reach the bounded `FMapReader` path. Whole-input
borrowed-slice APIs retain their explicit cap. The focused parser suite passed
21 unit, 4 integration, and 1 ignored doctest; source guards, inventory
freshness, snapshot validation, and `git diff --check` pass. A fresh consumer
compile and materialized late-content scanner fixture remain open because
Docker is unavailable. No host installation, remote execution, usage reset,
commit, push, or workflow action was used.

R06 cache-only consumer-build follow-up (2026-09-09): reused the existing host
and parser Cargo caches in a disposable combined cache and ran the consumer
check with `--locked --offline`. Cargo resolved dependencies but the host
`openssl-sys` build script stopped because `pkg-config` and discoverable
OpenSSL development headers are absent. No software was installed and no
network access was used; coherent consumer compilation remains unverified.

R06 derived OneStore/output collection safety refinement (2026-09-09): added
one bounded, fallible reservation path for parser-owned collections derived
after source materialization. TOC flattening, note-tag and ink-stroke outputs,
decoded ink paths, object reference vectors, revision group maps,
revision/object caches, and the OneStore object-space map now reserve under
the typed 64 MiB collection budget. Malformed ink dimensions and non-divisible
path lengths return parser errors rather than reaching arithmetic or slice
panics. The focused parser suite remains 21 unit, 4 integration, and 1
ignored doctest; consumer compile, materialized late-content evidence, and
full parser quota qualification remain open.

R06 shared reference-resolution safety refinement (2026-09-10): object and
object-space reference arrays now use bounded fallible output vectors;
reference-count aggregation detects overflow; and missing object-space
mappings are propagated instead of silently discarded. Embedded-ink and
note-tag property-set adapters use the same bounded compact-ID path. The
isolated offline parser-library check and its 21 unit tests passed. The full
workspace consumer build remains blocked on the host's absent OpenSSL
development headers; integration snapshots, materialized late-content
evidence, and full parser quota qualification remain open.

R06 high-level parse-result collection safety refinement (2026-09-10):
outline, page, table, section, page-series, image, and UTF-16 conversion
paths now use the shared bounded, fallible parser-result collector instead of
infallible result-collection growth. The isolated offline parser-library
check and its 21 unit tests passed; source guards, inventory freshness,
snapshot validation, and `git diff --check` passed across all 597 capability
entries. Consumer compilation, materialized late-content evidence,
integration snapshot rerun, and full parser quota qualification remain open.

R06 remaining parser collection safety refinement (2026-09-10): removed the
final infallible result/derived-vector collections across notebook loading,
FSSHTTP object lookup, rich text, table properties, outline indentation, ink
dimensions, number-list UTF-16 output, and signed ink paths. Non-aligned table
width and ink-dimension payloads are now explicit parser errors. The isolated
offline parser-library check and its 21 unit tests passed; all 597 source
guards, inventory freshness, snapshot validation, and `git diff --check`
passed. Snapshot integration rerun, consumer compilation, materialized
late-content evidence, and full parser quota qualification remain open.

R06 format-width and UTF-16 fail-visible refinement (2026-09-10): UTF-16
conversion rejects odd-width and invalid-surrogate payloads instead of
silently truncating or panicking; u16/u32 property vectors reject non-aligned
payloads before conversion. The isolated offline parser-library suite passed
23 unit tests; all 597 source guards, inventory freshness, snapshot
validation, and `git diff --check` passed. Snapshot integration rerun,
consumer compilation, materialized late-content evidence, and full parser
quota qualification remain open.

R06 checked rich-text reference refinement (2026-09-10): embedded-object
resolution now checks the derived text-run reference index and returns a
malformed parser error for style/object count disagreement instead of
indexing out of bounds. The isolated offline parser-library suite passed 23
unit tests; all 597 source guards, inventory freshness, snapshot validation,
and `git diff --check` passed. Full consumer compilation, snapshot
integration rerun, materialized late-content evidence, and full parser quota
qualification remain open.

R06 OneStore mapping identity refinement (2026-09-10): storage-index cell and
revision mappings, plus storage-manifest root declarations, now reject
duplicate keys rather than silently replacing an earlier keyed record. The
standalone current-source parser harness passed 45/45 unit tests, 4/4
reader-boundary tests, and the sparse path-streaming test. The full package
check remains blocked before compilation by the missing offline `insta` cache
entry; consumer compilation, materialized late-content evidence, snapshot
integration, and full parser quota qualification remain open.

R06 revision-root precedence refinement (2026-09-10): revision-chain merging
now preserves a newer revision's root when a base revision supplies the same
role, while duplicate root roles within one manifest are rejected as malformed
OneStore data. The standalone current-source parser harness passed 48/48 unit
tests, 4/4 reader-boundary tests, and the sparse path-streaming test. The full
package check remains blocked before compilation by the missing offline `insta`
cache entry; consumer compilation, materialized late-content evidence,
snapshot integration, and full parser quota qualification remain open.

R06 revision-manifest group-reference identity refinement (2026-09-10):
duplicate object-group references now fail closed during FSSHTTPB parsing
instead of being reprocessed. The standalone current-source parser harness
passed 48/48 unit tests, 4/4 reader-boundary tests, and the sparse
path-streaming test. Full package compile, consumer qualification, materialized
late-content evidence, snapshot integration, and full parser quota
qualification remain open.

R06 reader-boundary disposable integration verification (2026-09-10): a
standalone current-source harness ran the two reader-boundary cases against
the real `New Section 1.one` sample; short reads matched buffer parsing and a
256 MiB-plus logical stream completed without reading its padding. Both tests
passed. Snapshot integration remains unavailable because the host cache lacks
`insta`.

R06 bounded raw property-vector copy refinement (2026-09-10):
`one::property::simple::parse_vec` now uses the shared bounded collection
helper for raw byte-vector allocation, keeping that path under the typed
64 MiB collection budget. The isolated offline parser-library suite passed 23
unit tests and the disposable reader-boundary harness passed both integration
cases; all 597 source guards, inventory freshness, snapshot validation, and
`git diff --check` passed. Full consumer compilation remains blocked by the
host's absent OpenSSL development headers; materialized late-content evidence,
snapshot integration, and full parser quota qualification remain open.

R06 fail-closed malformed enum and path refinement (2026-09-10): unknown
note-tag shapes and object-group change frequencies now return typed malformed
data errors instead of panicking; notebook, section, and section-group path
metadata checks no longer use input-dependent `expect` calls. The isolated
offline parser-library suite passed 25 unit tests and the disposable
reader-boundary harness passed both integration cases; all 597 source guards,
inventory freshness, snapshot validation, and `git diff --check` passed. Full
consumer compilation remains blocked by the host's absent OpenSSL development
headers; a direct offline consumer recheck also stops earlier because the
locked `insta` crate is absent from the host cache. Materialized late-content
evidence, snapshot integration, and full parser quota qualification remain
open.

R06 fail-closed reference-range and ink-shape refinement (2026-09-10): object
and object-space reference arrays now reject overflow or out-of-stream ranges,
and missing object mappings are errors rather than silently discarded IDs. Ink
bounding-box vectors must contain exactly four values. Four direct malformed
range regressions were added; the isolated offline parser-library suite
passed 29 unit tests and the disposable reader-boundary harness passed both
integration cases. All 597 source guards, inventory freshness, snapshot
validation, and `git diff --check` passed. Full consumer compilation remains
blocked by the host's absent OpenSSL development headers; materialized
late-content evidence, snapshot integration, and full parser quota
qualification remain open.

R06 checked OneNote recursion-boundary refinement (2026-09-10): recursive TOC
traversal now enforces a shared 1024-level limit, and OneStore revision-base
traversal rejects cyclic manifests while bounding its visited set. The new
typed recursion-limit error is classified as a resource-limit failure. The
isolated offline parser-library suite passed 30 unit tests and the disposable
reader-boundary harness passed both integration cases; all 597 source guards,
inventory freshness, snapshot validation, and `git diff --check` passed. Full
consumer compilation remains blocked by absent host OpenSSL development
headers and the missing locked `insta` cache entry; materialized late-content
evidence, snapshot integration, and full parser quota qualification remain
open.

R06 checked FSSHTTPB payload-width refinement (2026-09-10): binary-item and
data-element-fragment `u64` payload sizes now pass through a checked
`read_vec_u64` conversion before materialization, and the compact-u64
defensive fallback returns a typed malformed-data error. The isolated offline
parser-library suite passed 31 unit tests and the disposable reader-boundary
harness passed both integration cases; all 597 source guards, inventory
freshness, snapshot validation, and `git diff --check` passed. Full consumer
compilation remains blocked by absent host OpenSSL development headers and the
missing locked `insta` cache entry; materialized late-content evidence,
snapshot integration, and full parser quota qualification remain open.

R06 OneStore property-vector width refinement (2026-09-10): the format's
`u32` byte-vector length now crosses the parser boundary through the checked
`u64` payload helper instead of an unchecked `as usize` narrowing. A direct
oversized-declaration regression was added. The isolated offline parser suite
passed 32 unit tests and the disposable reader-boundary harness passed both
integration cases; the full source/evidence guard passed all 597 capability
entries and the inventory, snapshot, and diff checks. Consumer compilation,
materialized late-content evidence, snapshot integration, and full parser
quota qualification remain open.

R06 bounded stream-window refinement (2026-09-10): stream reads larger than
the 64 KiB refill window now fail with a typed resource-limit error before any
buffer growth, preserving the reader's bounded sequential contract. The
isolated offline parser suite passed 33 unit tests and the disposable
reader-boundary harness passed both integration cases; the full source/evidence
guard passed all 597 capability entries and the inventory, snapshot, and diff
checks. Consumer compilation, materialized late-content evidence, snapshot
integration, and full parser quota qualification remain open.

R06 reader fault-boundary disposable verification (2026-09-10): the
standalone reader harness added deterministic mid-input truncation and source
read-failure cases. All four reader-boundary cases passed: short reads match
buffer parsing, logical input above the former cap completes, truncation is
reported as an unexpected EOF, and an injected source error remains an I/O
failure. This is development evidence only; consumer compilation,
materialized late-content evidence, snapshot integration, and full parser
quota qualification remain open.

R06 bounded embedded-data copy refinement (2026-09-10): embedded-file,
picture-container, and raw property-vector copies now use one fallible helper
under the 64 MiB derived-data budget instead of plain `to_vec()` duplication.
The isolated offline parser suite passed 34 unit tests and the disposable
reader-boundary harness passed all four cases; the full source/evidence guard
passed all 597 capability entries, with inventory, snapshot, and diff checks
clean. Consumer compilation, materialized late-content evidence, snapshot
integration, and full parser quota qualification remain open.

R06 checked data-element-fragment chunk refinement (2026-09-10):
`DataElementFragment` now validates the checked `offset + length` chunk range
against the declared total element size and reads only the declared chunk
length. A focused parser test proves a one-byte late chunk with a logical
total above 256 MiB does not become a contiguous allocation request; malformed
ranges remain fail-visible. The isolated offline parser suite passed 38 unit
tests and the disposable reader-boundary harness passed all four cases.
Consumer compilation, materialized late-content evidence, snapshot
integration, and full parser quota qualification remain open.

R06 bounded Latin-1 property conversion refinement (2026-09-10):
ASCII/Latin-1 property conversion now checks the resulting UTF-8 size against
the 64 MiB derived-data budget and uses fallible string reservation while
preserving byte-to-character behavior. The isolated offline parser suite
passed 39 unit tests and the disposable reader-boundary harness passed all
four cases. Source guards, inventory freshness, snapshot validation, and
`git diff --check` passed. Consumer compilation, materialized late-content
evidence, snapshot integration, and full parser quota qualification remain
open.

R06 OneStore packaging identity/version compatibility refinement (2026-09-10):
the packaging parser no longer requires `guidFile` to equal
`guidLegacyFileVersion`; the format defines these as independent package-store
identity and version GUIDs. Required fixed file-type and file-format GUIDs are
validated independently. A minimal packaging regression parses distinct
identity/version GUIDs and rejects invalid fixed GUIDs. The isolated offline
parser suite passed 41 unit tests and the disposable reader-boundary harness
passed all four cases. Consumer compilation, materialized late-content
evidence, snapshot integration, and full parser quota qualification remain
open.

R06 Data Element Fragment completion-marker refinement (2026-09-10): fragment
parsing now requires the format-defined Data Element End marker after the
opaque chunk. A focused regression rejects a truncated fragment with the
marker removed, while the large-logical-offset chunk case remains valid. The
isolated offline parser suite passed 42 unit tests and the disposable
reader-boundary harness passed all four cases. Consumer compilation,
materialized late-content evidence, snapshot integration, and full parser
quota qualification remain open.

R06 OneNote byte-slice parser-error preservation refinement (2026-09-10): the
public `scan_bytes` modern-parser attempt now preserves typed parser errors,
including resource-limit failures, instead of collapsing every failure to
generic `Parse`; a valid legacy marker still takes the compatibility path.
Source guards and the existing malformed modern fallback regression cover the
change. The parser-library suite remains 42/42 and the reader-boundary harness
remains 4/4. Consumer compilation, materialized late-content evidence,
snapshot integration, and full parser quota qualification remain open.

R06 OneStore root and packaging-schema validation refinement (2026-09-10):
the parser now validates the packaging cell-schema GUID against the two
format-defined OneNote types, requires the specified header Cell ID, and
requires the data-root Cell ID to identify the specified root object-space
GUID. The public byte-slice compatibility path also preserves typed parser
errors through its legacy fallback decision. The standalone current-source
parser harness passed 45/45 unit tests and the reader-boundary harness passed
4/4; the full source/evidence guard passed all 597 capability entries, with
inventory, snapshot, and diff checks clean. Consumer compilation,
materialized late-content evidence, snapshot integration, and full parser
quota qualification remain open.

R06 byte-slice fallback and CompactU64 coverage refinement (2026-09-10):
`scan_bytes` and `from_bytes` now restrict legacy fallback to format/parse
failures, preserving resource-limit, I/O, timeout, sink, and panic failures
instead of allowing a coincidental legacy marker to mask an incomplete modern
parse. CompactU64 tests now exercise representative values through all eight
supported wire widths. The standalone current-source parser harness passed
38/38 unit tests and 4/4 reader-boundary tests; the acceptance-case suite
passed. Consumer compilation, materialized late-content evidence, snapshot
integration, and full parser quota qualification remain open.

R06 path/notebook sequential-reader refinement (2026-09-10): the public
`Parser::parse_section` and `Parser::parse_notebook` APIs now parse opened files
through the bounded sequential `Reader` instead of first materializing the
whole file. Existing schema, filename, and section-group behavior is retained;
the borrowed-slice API remains explicitly bounded. The disposable current-
source parser harness passed 38/38 unit tests and 4/4 reader-boundary tests.
The full parser package check remains blocked before compilation by the missing
offline `insta` cache entry and absent host OpenSSL development headers;
materialized late-content evidence, snapshot integration, and full parser
quota qualification remain open.

R06 object-group declaration/data consistency refinement (2026-09-10): the
vendored FSSHTTPB parser now rejects object-group declaration/data variant
mismatches and object/cell reference counts that disagree with their parsed
data arrays, at the package parse boundary. OneStore object-space construction
also rejects duplicate object/partition declaration keys instead of silently
overwriting the earlier data. The standalone current-source parser harness
passed 41/41 unit tests, 4/4 reader-boundary tests, and the sparse path-
streaming test. The full parser package check remains blocked before
compilation by the missing offline `insta` cache entry; consumer compilation,
materialized late-content evidence, snapshot integration, and full parser
quota qualification remain open.

R06 FSSHTTPB duplicate-identifier refinement (2026-09-10): all seven typed
data-element package maps now reject duplicate element identifiers rather than
silently replacing an earlier parsed object. The focused current-source
parser harness passed 42/42 unit tests, 4/4 reader-boundary tests, and the
sparse path-streaming test. The full package check remains blocked before
compilation by the missing offline `insta` cache entry; consumer compilation,
materialized late-content evidence, snapshot integration, and full parser
quota qualification remain open.

R06 OneStore property-set identity refinement (2026-09-10): property-set
parsing now rejects duplicate property identifiers instead of overwriting the
earlier value and its position metadata. The standalone current-source parser
harness passed 43/43 unit tests, 4/4 reader-boundary tests, and the sparse
path-streaming test. The full package check remains blocked before compilation
by the missing offline `insta` cache entry; consumer compilation,
materialized late-content evidence, snapshot integration, and full parser
quota qualification remain open.

R10 IDSESSION report-correlation hardening (2026-09-10): clamdscan now parses
the structured report's top-level numeric request ID through the shared JSON
parser instead of a substring search that could match an ID embedded in a
nested object or alert text. Negative, out-of-range, wrong-type, nested-only,
and malformed IDs are rejected without modifying the caller's output. The
source gate and diff checks pass; current-source client execution remains
development-only, and certified R10/R04 evidence remains open.

R10 legacy IDSESSION correlation hardening (2026-09-10): the text-reply path
 now parses a positive decimal session ID only when the numeric prefix is
 immediately followed by the protocol colon. This removes `atoi()` prefix
 acceptance and resets the lookup pointer before every reply, so malformed or
 zero-prefixed replies cannot reuse a prior request entry. Focused parser
 regressions, source guards and consistency checks remain development evidence;
 certified R10/R04 evidence remains open.

R10 regular-stream mutation hardening (2026-09-10): the client stream sender
 now treats a regular descriptor's admitted `fstat()` size as an exact byte
 budget. Early EOF and growth after the admitted boundary fail before the
 terminator is sent, preventing a changed descriptor from becoming a clean
 prefix scan. The source guard and parser/protocol checks remain development
 evidence; certified R10/R04 evidence remains open.

R10 milter structured-frame cardinality hardening (2026-09-10): the milter
report receiver now accepts exactly one JSON report object for each
`INSTREAMREPORT`/`FILDESREPORT` request and requires its zero-length
terminator. A second frame is rejected instead of being merged into the
first result, preventing contradictory outcomes from being normalized into a
successful-looking milter decision. The source gate remains development
evidence; certified R10/R04 evidence remains open.

R10 shared structured-client frame cardinality hardening (2026-09-10): the
common `dsreport()` path now applies the same one-object-plus-terminator
contract used by `clamdscan` and the milter. A second frame is rejected before
it can increment detection/incomplete counters or be written as accepted
report output. A focused `check_clamd` regression covers the rejection; the
source gate remains development evidence and certified R10/R04 evidence
remains open.

R10 structured-report duplicate-key hardening (2026-09-10): the shared JSON
report parser now rejects duplicate top-level object names before JSON-C can
collapse them to one value, including escaped spellings of the same key. The
parser also rejects report lengths that cannot be represented by JSON-C's
signed-length API. Focused ID/status regressions, source guards, inventory,
snapshot validation, and `git diff --check` pass; no certified or full-size
R10/R04 evidence is claimed.

R06 notebook traversal failure-visibility refinement (2026-09-10): notebook
TOC traversal still skips genuinely deleted section paths for compatibility,
but now propagates metadata errors other than `NotFound` and rejects TOC
entries that are neither regular section files nor directories. This prevents
permission and special-file failures from silently becoming a partial,
successful notebook. The focused standalone parser suite remains 48/48;
source guards and diff checks pass, while consumer compilation, materialized
late-content evidence, and full parser quota qualification remain open.

R10 on-access unknown-size stream ceiling hardening (2026-09-10): the private
on-access stream sender now clamps both zero and above-ceiling direct-call
limits to the certified 32-GiB ingress ceiling. This closes a defense-in-depth
gap for non-regular descriptors whose context bypasses option parsing; regular
file preflight and the descriptor-passing path already enforce the same bound.
The source gate and diff checks remain required; no certified on-access or R04
acceptance evidence is claimed.

R06 OneStore reference-count narrowing hardening (2026-09-10): object and
object-space predecessor reference counts now use checked `u32` to `usize`
conversion instead of unchecked casts before offset arithmetic. This keeps
cross-target parser behavior fail-closed and preserves the existing checked
range/overflow validation. Focused regressions and the full source gate pass;
no certified parser or R04 acceptance evidence is claimed.

R10 on-access stat classification hardening (2026-09-10): on-access stream and
FILDES ingress now reject negative `fstat()` sizes as `CL_ESTAT` before applying
the 32-GiB limit. This keeps invalid source metadata distinct from a genuine
size admission refusal and matches the shared client-side descriptor contract.
Source guards and diff checks remain required; no certified on-access or R04
acceptance evidence is claimed.

R10 on-access entry-point stat classification hardening (2026-09-10): the
scan-thread entry point now rejects a caller-supplied negative `st_size` as
`CL_ESTAT` before the signed value can be cast for the effective-limit check.
This closes the pre-protocol path that could otherwise relabel malformed
metadata as `CL_EMAXSIZE`. Source guards and diff checks remain required; no
certified on-access or R04 acceptance evidence is claimed.

R10 on-access worker stat classification hardening (2026-09-10): directory
extra-scans and permission-event preflight now reject negative `st_size` values
as `CL_ESTAT` before their local size-limit comparisons. The worker clears the
scan action for malformed metadata, keeping inotify and fanotify paths
fail-visible without unsigned-wrap classification. Source guards and diff
checks remain required; no certified on-access or R04 acceptance evidence is
claimed.

R10 unknown-size on-access stream parity (2026-09-10): non-regular on-access
descriptors now stream to EOF under the bounded ceiling instead of treating
`fstat().st_size == 0` as an empty input. A one-byte overflow probe returns
`CL_EMAXSIZE` without sending a terminating frame, and source read failures
remain `CL_EREAD`. Source guards and diff checks remain required; no certified
on-access or R04 acceptance evidence is claimed.

R10 on-access report cardinality hardening (2026-09-10): the on-access
structured-report receiver now rejects a second nonzero report frame instead
of merging multiple daemon responses into one verdict. It therefore enforces
the one-report-plus-terminator protocol used by the other private clients.
Source guards and diff checks remain required; no certified on-access or R04
acceptance evidence is claimed.

R06 nested OneNote traversal depth hardening (2026-09-10): outline groups,
outline elements, table rows/cells, and table-contained content now share the
vendored parser's checked recursion budget. This closes the outline/table
object-graph cycle that could otherwise recurse without the TOC-only depth
guard. Source guards and diff checks remain required; no certified parser or
R04 acceptance evidence is claimed.

R04 structured resource-phase binding (2026-09-10): acceptance records now
reject bare resource labels and require measured RSS/temporary budget tokens,
or the explicit development-envelope max-file/max-temp form. PCRE records also
require the PCRE and post-PCRE phase tokens. Focused schema, producer, service,
readiness, inventory, and source-gate checks pass; the authoritative records
file remains empty and no capability was promoted.

R09 fuzzy-image working-set admission hardening (2026-09-10): the reader-backed
image path now derives its reservation from decoder pixel count plus declared
output bytes and checked transform overhead, avoiding under-reservation for
low-byte-per-pixel images while remaining independent of encoded source size.
Focused R09/R04 controls and the full source gate pass. The two required R09
matcher rows remain pending until certified implementation/evidence is
available; offline Cargo compilation remains blocked by the uncached `insta`
dependency.

R06 packaging-reference binding (2026-09-10): OneStore parsing now resolves
the storage index named by the FSSHTTPB packaging header instead of selecting
an arbitrary first map entry. A focused two-index lookup regression, snapshot
and inventory checks, and the full source gate pass. Consumer compilation,
materialized late-content evidence, and full parser quota qualification remain
open.

R10/R13 on-access known-size early-EOF hardening (2026-09-10): the on-access
INSTREAM sender now treats EOF before the admitted regular-file size as
`CL_EREAD` and closes without a terminator, while retaining normal EOF for
unknown-size descriptors. This prevents a shrinking regular file from
entering a zero-length-chunk loop or being represented as a clean prefix.
Source guards, inventory freshness, diff checks, and the full source gate pass;
certified on-access and R04 evidence remain open.

R06 nested OneStore property-set recursion hardening (2026-09-10): nested
`PropertySet`/`PropertyValue` parsing now shares the checked parser depth
budget. A 1024-depth development probe exposed that the previous nominal
budget itself could exhaust the test thread stack; the shared budget is now
128, still well above normal format nesting. The disposable current-source
parser harness passed 49/49 unit tests, including deep nesting; full source
guards pass, while consumer compilation and certified parser evidence remain
open.

R06 nested reference-count traversal refinement (2026-09-10): OneStore object
and object-space reference-offset accounting now descends through both
`ArrayOfPropertyValues` and child `PropertySet` nodes. The traversal is
iterative and reserves its pending worklist through the parser collection
budget, so deeply nested property graphs cannot overflow the call stack or
silently omit references from the OIDs/OSIDs offsets. A 2048-level
current-source regression passed for both reference kinds; the standalone
parser harness passed 52/52 unit tests and the full source gate passed. This
remains development verification only; consumer compilation, materialized
late-content evidence, and certified parser/R04 qualification remain open.

R06 storage-manifest mapping refinement (2026-09-10): OneStore parsing now
resolves the storage manifest named by the storage-index manifest mapping. A
package with no mapping remains compatible when it contains exactly one
manifest, while ambiguous unmapped manifests and multiple mappings fail
closed instead of selecting an arbitrary hash-map entry. The standalone
current-source parser harness passed 55/55 unit tests and the full source
inventory/guard checks passed. Consumer compilation, materialized late-content
evidence, and certified parser/R04 qualification remain open.

R09 GGUF structural-admission refinement (2026-09-10): recognized GGUF AI
model files now pass through a bounded structural parser for versions 1--3.
It validates metadata value types and nested-array depth, the optional
`general.alignment` field, tensor descriptors, and aligned tensor-data
offsets without materializing model payloads. ONNX/TensorFlow Lite recognition
and malformed/truncated GGUF remain explicit incomplete/non-cacheable results,
and the outer raw matcher remains mandatory. A valid minimal GGUF boundary and
the non-GGUF unsupported boundary are registered in the required-unsupported
development group; full tensor-shape/type validation and certified evidence
remain open.

The GGUF alignment check also enforces the format's minimum 8-byte alignment,
with a required-group regression for a `general.alignment=4` metadata entry.
This remains a bounded development refinement; no capability was promoted and
certified parser or release evidence is still required.

The same required group now proves a structurally valid GGUF can still return a
raw signature detection from its payload area, keeping the outer matcher
mandatory even when structural admission succeeds.

R06 legacy reader-window arithmetic refinement (2026-09-10): corrected the
reader's remaining-input calculation so a scan start is subtracted once, not
twice. A late-marker regression now exercises a valid attachment beyond the
first 1 MiB window; consumer compilation and certified OneNote qualification
remain open.

R10 on-access source-read interruption refinement (2026-09-10): the private
on-access stream sender now retries `EINTR` for its chunk read and both
boundary probes. Signals cannot turn a resumable source read into `CL_EREAD`,
while genuine read failures remain fail-closed and no terminating frame is
sent after a failed request. This is source/control evidence only; certified
on-access and R04 acceptance evidence remain open.

R10 on-access version-frame validation refinement (2026-09-10): the private
version handshake now requires one complete NUL-terminated `ClamAV ` frame
before printing or returning success. Empty, malformed, and absent replies
remain fail-visible and use the caller's explicit local-version fallback.
This is source/control evidence only; certified on-access and R04 acceptance
evidence remain open.

R10 legacy terminal-outcome validation refinement (2026-09-10): the shared
legacy reply parser now admits only `OK`, `FOUND`, and `ERROR` terminal
suffixes. Common `dsresult()` and IDSESSION `dspresult()` reject unknown or
unterminated replies rather than correlating them and allowing malformed text
to look clean. Focused parser coverage is development evidence only; certified
R10 and R04 acceptance evidence remain open.

R10 legacy short-reply shape refinement (2026-09-10): the shared legacy reply
parser now also requires a colon-bearing clamd reply. Bare short `OK`,
`FOUND`, and `ERROR` frames cannot pass the consumers' old length guard as an
implicit clean result. Focused parser coverage is development evidence only;
certified R10 and R04 acceptance evidence remain open.

R10 clamdscan version-frame validation refinement (2026-09-10): the regular
`clamdscan` version path now requires one nonempty `ClamAV ` response and
returns its existing fallback status for absent, malformed, or repeated
frames. This prevents arbitrary daemon text from being printed as a successful
version result. Certified R10 and R04 acceptance evidence remain open.

R10 clamdscan empty-walk failure return refinement (2026-09-10): the serial
walker now returns failure when `cli_ftw()` records an error before visiting a
file; only an error-free empty walk uses the historical “No files scanned”
success result. Certified R10 and R04 acceptance evidence remain open.

R10 reload-frame validation refinement (2026-09-10): `clamdscan` now requires
 the exact NUL-terminated `RELOADING` response before reporting a successful
 database reload; extra or missing response bytes remain fail-visible.

R06 UTF-16 quota-error propagation refinement (2026-09-10): `simple::parse_string()`
 now preserves typed collection/allocation failures returned by bounded UTF-16
 conversion instead of relabeling them as generic malformed data. The
 standalone current-source OneNote module harness passes 17/17, while the full
 parser-package `insta` cache, host OpenSSL development headers, materialized
late-content evidence, and certified parser qualification remain unavailable.

R06 sequential-reader interruption refinement (2026-09-10): the vendored
OneNote reader now retries `Interrupted` stream reads, preserving resumable
source reads instead of surfacing a spurious parser I/O failure. The current
source module harness remains 17/17; the parser-package `insta` cache, host
OpenSSL development headers, materialized late-content evidence, and certified
parser qualification remain unavailable.

R06 legacy-reader interruption refinement (2026-09-10): the chunked legacy
OneNote reader now retries interrupted magic, scan-window, header, and payload
reads. The injected-interruption regression passes in the current-source
module harness; certified parser and full-size evidence remain unavailable.

R09 GGUF duplicate-alignment refinement (2026-09-10): the bounded GGUF parser
now rejects repeated `general.alignment` metadata instead of silently letting a
later value replace the earlier alignment. A required-group regression covers
conflicting duplicate values; certified parser and full-size evidence remain
unavailable.

R09 GGUF tensor-layout refinement (2026-09-10): tensor offsets are now treated
as relative to the tensor-data blob and must advance contiguously by each
alignment-padded tensor size. A required-group overlap regression passes;
certified parser and full-size evidence remain unavailable.

R09 GGUF tensor-rank refinement (2026-09-10): tensor descriptors now reject
rank values above the four-dimensional GGML limit before dimension-vector
reads. A complete five-dimension descriptor regression is registered;
certified parser and full-size evidence remain unavailable.

R09 GGUF metadata-key refinement (2026-09-10): empty metadata keys now fail
closed before value parsing, with a required-group regression registered;
certified parser and full-size evidence remain unavailable.

R09 GGUF quantized-tensor geometry refinement (2026-09-10): established GGML
F32/F16, Q4/Q5/Q8, K/IQ, integer, and BF16 block geometries are now validated
before checked contiguous tensor-layout accounting. Q4_0 valid and
block-misaligned regressions are registered; full model semantics and
qualification remain unavailable.

R09 GGUF current-quantized-type refinement (2026-09-10): the bounded GGUF
geometry table now admits the current TQ1_0, TQ2_0, MXFP4, NVFP4, Q1_0, and
Q2_0 block formats with checked block-shape and byte-size accounting. A
table-driven required-group regression covers one aligned block of every new
type; linked, sanitizer, certified, and full-model qualification remain open.

R09 raw-only status-boundary correction (2026-09-10): the `cli_magic_scan()`
raw-only fast path now merges matcher status with a prior parser/incomplete
status. A clean raw pass can no longer erase the fail-visible result for a
recognized type whose required parser is unavailable, while a raw malware
detection retains precedence. The local 145-test tools suite (2 expected
skips), snapshot check, diff check, and full source guard passed; no capability
was promoted and certified/full-size evidence remains open.

R09 bounded Python-bytecode parser (2026-09-10): recognized Python compiled
inputs now use a non-executing marshal structural walker with bounded object
count, recursion depth, lengths, references, and fmap offsets. The parser
supports legacy and modern code-object layouts and merges with raw matching;
truncated input remains fail-visible and non-cacheable. Required-group tests
cover truncated, legacy, modern, and raw-detection-precedence fixtures. The
145-test local tools suite
(2 expected skips), snapshot check, diff check, and full source guard passed;
no capability was promoted and independent format-8, certified, full-size,
and linked current-source evidence remain open.

R09 Python-marshal reference-table hardening (2026-09-10): malformed
`TYPE_REF|FLAG_REF` tokens are now rejected, dictionary keys are included in
the bounded object/reference accounting, and valid references to flagged
dictionary keys remain accepted. Focused regressions cover out-of-range,
flagged, and dictionary-key references. The local 145-test tools suite
(2 expected skips), fresh inventory/snapshot checks, diff check, and full
source guard passed; current-source C linkage and certified/full-size
qualification remain open.

R10 on-access report-command length hardening (2026-09-10): on-access
`CONTSCAN`/`MULTISCAN`/`ALLMATCHSCAN` report commands now use checked `size_t`
length arithmetic and bounded `snprintf` construction. An overflowing or
unrepresentable command is rejected before allocation or transport, removing
the prior wrapped-length `sprintf` path. The local 145-test tools suite
(2 expected skips), inventory/snapshot checks, diff check, and full source
guard passed; host C syntax checking remains blocked by missing OpenSSL
headers and certified R10 evidence remains open.

R06 notebook TOC path and recursion hardening (2026-09-10): notebook TOC
entries now admit only safe relative paths, inspect referenced entries with
`symlink_metadata`, and refuse symlinked nested TOC files instead of following
them. Nested notebook/group traversal shares the bounded parser recursion
budget, preventing filesystem-backed TOC cycles from recursing indefinitely.
The current-source OneNote module harness compiles and passes 18/18; the full
parser test profile remains blocked by the uncached offline `insta` dependency,
and consumer/certified qualification remains open.

R09 TFLite structural-admission slice (2026-09-10): recognized `TFL3` model
inputs now pass through a bounded FlatBuffer validator that checks the root
table, signed vtable relation, field offsets, direct table-vector topology,
string termination, and required nonempty subgraph vector without materializing
model weights. Invalid root/vector boundaries remain incomplete and
non-cacheable, the outer raw matcher remains mandatory, and ONNX remains an
explicit unsupported boundary. The focused cases are registered but cannot be
executed against a current-source C link on this host; full nested-model
semantics, production model corpus, sanitizer, certified Linux x86-64, and
release qualification remain open.

R09 TFLite field-width refinement (2026-09-10): present Model-table fields now
require the complete four-byte FlatBuffer uoffset to fit inside the table's
declared object size, closing a malformed-table read boundary that previously
could consume bytes beyond the declared object while still reaching a valid
vector. The new `test_ai_model_tflite_field_width_is_fail_visible` regression
is source-registered; the current-source C test binary is unavailable on this
host, while nested-model semantics, production corpus, sanitizer, certified
Linux x86-64, and release qualification remain open.

R09 ONNX structural-admission slice (2026-09-10): recognized ONNX inputs now
pass through a bounded protobuf wire-format walker. It requires the
`ModelProto` IR version, graph, and operator-set import fields, including each
operator-set version; checks field numbers, wire types, varint/fixed-width
ranges, length-delimited ranges, and bounded nesting/field counts; and
recursively validates known graph, node, attribute, tensor, sparse-tensor, and
metadata message paths without copying model strings or tensor payloads.
Skipped length-delimited payloads now checkpoint the shared scan deadline.
Malformed/truncated ONNX remains incomplete and non-cacheable, while the outer
raw matcher remains mandatory. The valid ModelProto, missing-graph,
nested-truncation, and missing-operator-set-version regressions are registered
but cannot be executed against a current-source C link on this host; full ONNX
tensor/type/operator semantics, production corpus, sanitizer, certified Linux
x86-64, and release qualification remain open.

R06 modern-reader panic-boundary refinement (2026-09-10): the scanner-facing
`OneNote::scan_reader` entry point now converts panics from the reader, parser,
or extraction callback boundary into `OneNoteParserPanic`, matching the
existing `scan_bytes` containment contract instead of allowing a direct Rust
consumer to unwind. The standalone current-source OneNote harness compiled
and passed 19/19 tests, including an injected reader-panic regression. This
is implementation/development evidence only; consumer compilation,
materialized late-content evidence, snapshot integration, certified runner,
and full parser quota qualification remain open. No software, remote
execution, Docker, usage reset, commit, push, or GitHub workflow action was
used.

R06 legacy-reader panic-boundary refinement (2026-09-10): the direct
`scan_legacy_reader` API now converts panics from its reader or attachment sink
into `OneNoteParserPanic` and invokes the sink abort hook before returning.
The current-source module harness adds a regression for a panicking seek path
and verifies sink cleanup; consumer compilation, materialized late-content
evidence, certified runner, and full parser qualification remain open.

R10 legacy path-command bounds refinement (2026-09-10): common `dsresult()`
and `dsreport()` path requests now share a checked command builder that rejects
size arithmetic overflow, lengths that cannot be represented by `sendln()`,
allocation failure, and formatting truncation before transport. The legacy
`sprintf` path is gone, and a registered `check_clamd` regression verifies the
normal `CONTSCAN` wire command remains exact; current-source C execution,
certified ingress, and R04 acceptance evidence remain open.

R10 milter structured-reply size hardening (2026-09-10): infected structured
milter reports now use a shared checked reply-size contract capped by
`CLI_MAX_ALLOCATION` before allocation, and reject negative or truncated
`snprintf()` results instead of continuing with a partial alert. The quota
regression covers empty, normal, overflow, over-limit, and NULL-output cases;
the linked test remains blocked on the host's missing OpenSSL development
headers, while source guards and certified milter/R04 evidence remain open.

R10 quarantine destination-path size hardening (2026-09-10): common move/copy
and hard-link quarantine flows now share a checked destination-path builder.
Directory/name/suffix arithmetic, suffix range, `INT_MAX` representability,
allocation, and `snprintf()` truncation are rejected before a path is opened,
linked, or returned; the prior `sprintf()` calls are gone. Inventory,
snapshot, tools, and source guards passed. Current-source C execution,
certified ingress, and R04 evidence remain open.

R06 reader offset-overflow hardening (2026-09-10): the vendored OneNote
reader-backed parser now checks buffer refill endpoints, truncation endpoints,
and stream cursor advancement before using them for allocation or slicing.
The focused `usize` overflow regression is registered and the source/evidence
controls remain the available verification; the offline parser test profile is
still blocked by the uncached `insta` dependency, while streaming embedded-file
extraction, certified builds, and full-size R06 qualification remain open.

R09 Python modern marshal-layout correction (2026-09-10): the bounded Python
compiled-bytecode walker now models Python 3.11+ code objects with six leading
integers and eight object fields, followed by the first-line, line-table, and
exception-table objects. This corrects the earlier five-leading interpretation
and keeps the modern fixture aligned with the locally generated CPython 3.11
marshal sequence, including `co_nlocals`. Source/evidence controls passed;
direct C execution, independent format-8 evidence, certified builds, and
production qualification remain open. Receipt:
`docs/largefile-task-receipts/R09-python-modern-layout-2026-09-10.md`.

R09 Python 3.11 marshal revalidation (2026-09-11): a locally generated CPython
3.11 marshal stream was inspected and confirmed to contain six leading
uint32 fields, including `co_nlocals`; the current scanner layout and modern
regression fixture now use that shape. Host tooling passed 147 tests with 2
expected skips, the 597-row acceptance map and 14-record schema passed,
snapshot/shell/diff controls passed, and no linked C execution was claimed
because the host lacks the required OpenSSL development headers. The Python
parser remains pending for certified/full-size qualification. Receipt:
`docs/largefile-task-receipts/R09-python-modern-layout-2026-09-10.md`.

R09 ONNX nested-message kind correction (2026-09-10): the bounded ONNX
protobuf walker now uses an explicit opaque message kind for recognized
length-delimited message families whose full schema is not interpreted. This
prevents valid `NodeProto.metadata_props`, device-configuration, sparse-tensor,
and newer model payloads from inheriting an unrelated `AttributeProto` or
metadata field contract, while retaining bounded field, wire, length, depth,
and deadline checks. The registered `test_ai_model_onnx_accepts_node_metadata_properties`
fixture covers a valid nested metadata path; inventory, snapshot, diff, and
full source guards passed. Current-source linked C execution, production ONNX
corpus, sanitizer, certified Linux x86-64, and release qualification remain
open. Receipt: `docs/largefile-task-receipts/R09-onnx-message-kind-correction-2026-09-10.md`.

R09 GGUF scalar-rank compatibility correction (2026-09-10): the bounded GGUF
validator now accepts rank-zero scalar tensors, which the reference ggml
reader represents with implicit one-valued remaining dimensions. The existing
maximum-rank and checked tensor-geometry/data-range rules remain in force; a
new aligned scalar F32 fixture requires a clean cacheable result. Inventory,
snapshot, diff, and source/evidence guards are refreshed after the correction.
Complete GGUF semantics, production model corpus, sanitizer, certified Linux
x86-64, and release qualification remain open. Receipt:
`docs/largefile-task-receipts/R09-gguf-scalar-rank-correction-2026-09-10.md`.

R09 GGUF zero-element tensor compatibility correction (2026-09-10): the
bounded GGUF validator now preserves a zero total element count for
format-valid non-negative shapes instead of rejecting any zero dimension.
Reference GGML accepts such tensors, including empty data sections; the new
aligned F32 regression keeps the existing rank, type, block, offset, and range
checks active. Inventory, snapshot, diff, and source/evidence guards remain
the available development verification; complete GGUF semantics, certified
builds, and release qualification remain open. Receipt:
`docs/largefile-task-receipts/R09-gguf-zero-element-tensor-2026-09-10.md`.

R09 GGUF signed-dimension range hardening (2026-09-10): tensor dimensions
above `INT64_MAX` are now rejected before zero-element product handling,
matching the reference GGML reader's signed dimension storage and preventing
high-bit values from being admitted as valid geometry. The new required-group
regression requires a cleared verdict and non-cacheable parse failure;
inventory, snapshot, diff, and source/evidence guards remain the available
development verification. Complete GGUF semantics, certified builds, and
release qualification remain open. Receipt:
`docs/largefile-task-receipts/R09-gguf-dimension-range-2026-09-10.md`.

R04 lifecycle fixture-binding correction (2026-09-11): lifecycle-bound
acceptance records now require a named `fixture_role` and the
`provenance/service-inputs-before.json` identity sidecar. A retained fixture
artifact alone cannot satisfy a record that claims daemon health/cleanup
lifecycle evidence. Added regressions for missing role and missing sidecar;
the focused acceptance schema passes 12/12, the full tools suite passes
145 tests with 2 expected skips, and the complete source guard passes. The
authoritative acceptance-record file remains empty; no capability status was
promoted and certified Linux x86-64/full-size qualification remains blocked.

R09 GGUF quantized row-shape refinement (2026-09-11): the bounded GGUF
geometry checker now validates the innermost row dimension against the
quantization block size, rejecting a `16x2` Q4_0 tensor whose total element
count would otherwise appear block-aligned. The required-group regression is
registered and the source/control sweep passes. No fresh linked C execution is
claimed because the available ARM64 Docker image lacks the test/development
libraries and no package installation was authorized; full tensor semantics,
certified x86-64, and release qualification remain open.

R09 GGUF tensor-name boundary refinement (2026-09-11): the bounded model
parser now rejects names at the reference 64-byte `GGML_MAX_NAME` limit before
skipping their payload. The regression uses a complete descriptor and payload
so it exercises the name rule rather than truncation; the source/control sweep
passes. No linked C execution is claimed because the available ARM64 Docker
image lacks the test/development libraries and no package installation was
authorized.

R09 TFLite metadata-buffer vector coverage hardening (2026-09-11 UTC): the
bounded FlatBuffer walk now explicitly documents and tests
`Model.metadata_buffer` as a scalar `int32` vector, matching the schema, and
keeps each buffer index out of the table-offset walker. The required-
unsupported group adds a valid model with two buffer tables and metadata-buffer
index one. Source/evidence guards remain green; linked current-source C
execution, certified x86-64, full-size evidence, and release qualification
remain open.

R09 TFLite metadata-buffer index-binding hardening (2026-09-11 UTC): the
bounded FlatBuffer walk now validates each signed `metadata_buffer` entry
against the declared `buffers` vector count, rejecting negative and
out-of-range indices as incomplete before accepting the model. The registered
regression changes the valid two-buffer fixture to index two and requires
`CL_EPARSE`, a cleared verdict, and cache taint. Source/evidence guards remain
green; linked current-source C execution, certified x86-64, full-size
evidence, and release qualification remain open.

R10 argument-separator parser hardening (2026-09-11 UTC): argument-taking
clamd commands now require the protocol's literal space separator before
accepting a path, so malformed `SCANfoo` input cannot be matched as `SCAN` with
the first path byte discarded. The existing daemon compatibility matrix adds
that malformed form across prefixed NUL/newline and legacy packet modes and
requires `UNKNOWN COMMAND`. Source/evidence guards remain green; a fresh
current-source daemon binary, certified/full-size ingress records, and R04
qualification remain open.

R09 signed TFLite metadata-buffer index hardening (2026-09-11 UTC): the bounded
FlatBuffer walk now decodes `Model.metadata_buffer` entries as signed `int32`
values before buffer-count admission, explicitly rejecting negative indices.
The required-unsupported group adds a valid-shape fixture with an `-1` entry
and requires `CL_EPARSE`, a cleared verdict, and cache taint. Source/evidence
guards remain the available verification; linked current-source C execution,
certified Linux x86-64, full-size evidence, and release qualification remain
open.

R09 fuzzy-image build correction (2026-09-11 UTC): the disposable current-
source CMake build exposed an ambiguity in `u64::from(...)` after the
pixel-count reservation added `num_traits::NumCast` to scope. The two `u32`
image dimensions now widen explicitly before checked multiplication, restoring
Rust compilation without changing the admission policy. Fresh executable
evidence remains in progress; no capability promotion or certified/full-size
claim is made.

R09 TFLite compile correction (2026-09-11 UTC): the disposable current-source
CMake build exposed a C redeclaration in the TFLite field helper. The local
vtable offset now uses `vtable_field_offset` instead of reusing the
`field_offset` output-parameter name; behavior and admission policy are
unchanged, and ARM64 executable evidence remains in progress.

R09 AI-model test/build corrections (2026-09-11 UTC): AI-model unit fixtures
now explicitly enable parser execution; GGUF final-payload admission no longer
requires padding after the final tensor; and Python/GGUF raw-marker fixtures
use their actual marker offsets while checking parser status separately from
`verdict_out`. ARM64 execution remains local development evidence only.

Current-source production-linked ARM64 parser checks (2026-09-11 UTC): the
fresh CMake-linked test binary passes the required-unsupported group 38/38,
the backend-enabled RAR group 11/11, the bounded fuzzy-image/GIF group 16/16,
and each of `rust_onenote`, `onenote`, and `rust_map` 2/2. These reruns cover
the current R09 implementation paths through the production C ABI after the
TFLite, GGUF, AI-model, and fuzzy-image build/test corrections. They remain
development evidence only: no certified x86-64, independent format-8,
sanitizer, production-CVD/service, materialized-large-file, or release
qualification evidence is present. Receipt:
`docs/largefile-task-receipts/R09-production-linked-arm64-2026-09-11.md`.

Daemon protocol test cleanup (2026-09-11 UTC): the bounded legacy-reply parser
now accepts clamd's `Excluded` directory result as a clean skip while keeping
unknown terminal text fail-closed. The bounded path-request unit fixture now
uses the normal clean-state `printok=1`. The container-native clamd rerun had
isolated 2 failures in these parser/test paths; current-source rebuild and
rerun remain required. Certified x86-64/full-size qualification and R04
service evidence remain open.

Daemon protocol rerun correction (2026-09-11 UTC): after rebuilding the
affected current-source targets, the focused `check_clamd` suite passed
118/118 checks, including the bounded path-request case and `ExcludePath`
legacy reply handling. The Python wrapper cases for `check_clamd` and
`clamdscan_ExcludePath` each passed 1/1. The combined current-source linked
CTest set (`libclamav`, `clamd`, and all `largefile_*` controls) passed 10/10;
certified x86-64/full-size qualification and R04 service evidence remain
open.

R04/R10 development-service input-binding correction (2026-09-11 UTC): the
current-source service capture initially exposed that lifecycle-bound records
were missing the required `provenance/service-inputs-before.json` identity
sidecar. The producer now retains version-1 before/after identities for each
small development fixture, binds both sidecars into every direct structured
and clamdscan record, and fails if the identities change during the capture.
The focused producer/schema tests passed 6/6 and 12/12; the corrected
current-source ARM64 daemon/client capture passed all 24 records, and an
independent host-side verifier accepted 24/24 with matching before/after
sidecars. This is development evidence only; no capability was promoted and
certified x86-64, full-size, sanitizer, privileged, and release qualification
remain open. Receipt:
`docs/largefile-task-receipts/R10-development-service-input-binding-2026-09-11.md`.

R04 development-capture trust-root correction (2026-09-11 UTC): the current
source `clamscan` producer previously allowed an omitted CA directory to fail
inside database loading with no structured report. It now defaults to the
repository's existing test trust root and rejects a missing or symlinked
explicit path before starting cases. Focused producer tests passed 2/2, the
real disposable ARM64 capture without a CA argument wrote and independently
validated all six file/stdin clean, detection, and limit records, and the
service producer tests remained 6/6. This improves development reproducibility
only; no capability was promoted and certified x86-64/full-size/sanitizer
qualification remains open. Receipt:
`docs/largefile-task-receipts/R04-development-capture-certs-2026-09-11.md`.

R00 five-issue current-source verification (2026-09-11 UTC): the disposable
current-source ARM64 production-linked cases passed required_unsupported 38/38,
RAR 11/11, fuzzy-image/GIF 16/16, Rust OneNote 2/2, legacy OneNote 2/2, Rust
map 2/2, parser regressions 4/4, descriptor map 2/2, CVD API 13/13 with the
repository test CA, CVD info 1/1, and the daemon option-parser 31/31. The host
tools suite passed 147 tests with 2 expected skips; the 597-row source guard,
fresh snapshot, and diff checks passed. The release gate correctly remains
blocked at 0 qualified, 440 pending, and 583 blockers. This is development
evidence only; certified Linux x86-64, sanitizer, full-size, production-CVD/
service, materialized-late-content, and final-canary evidence remain open.
Receipt: `docs/largefile-task-receipts/R00-five-issue-verification-2026-09-11.md`.

R00 five-issue hardening and verification (2026-09-11 UTC): the focused
production-linked ARM64 checks passed PDF 24/24, ARJ map/status 8/8, EGG
map/cleanup 12/12, callback/report API 4/4, and GIF/fuzzy-image 16/16. The
fuzzy-image Rust FFI loader now uses fallible reservations for its hashmap and
per-hash metadata vectors and returns allocation failure through `FFIError`
instead of panicking across the extern boundary; a multiple-metadata-record
regression and source guards pin the path. The generated inventory and
snapshot were refreshed; the source guard, 147-tool-test suite with 2 expected
skips, snapshot freshness, and diff checks passed. The exact linked binary
predates the final Rust-only edit because the disposable CMake graph lacks
`libcheck_pic.a` and related development artifacts, so the new allocation
hardening is source-verified rather than claimed as linked evidence. The gate
remains blocked at 0 qualified, 143 bounded, 440 pending, and 583 blockers;
certified x86-64, sanitizer, full-size, production-CVD/service, materialized
edge, and final-canary evidence remain open. Receipt:
`docs/largefile-task-receipts/R00-five-issue-hardening-2026-09-11.md`.

R06 object-space reference stream correction (2026-09-11 UTC): the embedded-
ink and note-tag nested property helpers previously sliced the ordinary
`object_ids` stream while resolving object-space references. Both now use the
dedicated `object_space_ids` stream. A parsed-property regression with distinct
compact IDs passed in the isolated current-source OneNote parser library
profile, 61/61 tests; the full source guard passed all 597 capability bindings,
the host tool suite passed 147 tests with 2 expected skips, and snapshot,
inventory, and diff checks passed. The canonical package test remains blocked
before compilation by the uncached `insta` dependency; no consumer, full-size,
certified, or R04 qualification evidence was produced. Release readiness is
unchanged and blocked. Receipt:
`docs/largefile-task-receipts/R06-object-space-reference-stream-2026-09-11.md`.

R06 modern-first OneNote fallback correction (2026-09-11 UTC): the scanner
now gives the reader-backed modern parser first refusal before scanning for
legacy attachment markers, because the legacy 16-byte magic is shared by
newer section files. Legacy fallback is restricted to modern format/parse
failures with the exact shared magic, and a no-attachment compatibility pass
preserves the original modern error. The focused scanner fallback unit,
147-host-test suite with 2 expected skips, 597-entry source guard, snapshot,
and diff checks passed. The canonical Rust consumer check remains blocked
before compilation by the uncached `insta` dependency; no consumer,
materialized-edge, certified, or release qualification evidence was produced.
Receipt: `docs/largefile-task-receipts/R06-modern-first-fallback-2026-09-11.md`.

R09 TFLite vtable boundary hardening (2026-09-11 UTC): the recognized AI-model
validator now rejects zero/negative-signed vtable distances and vtables that
extend past their containing table. The host tools suite passed 147 tests with
2 expected skips, the 597-entry source guard, fresh snapshot check, and diff
check passed. The current-source ARM64 C/Rust build probes remain blocked before
compilation by missing `zconf.h` and an incomplete offline dependency cache; no
software was installed, no capability was promoted, and release readiness
remains blocked.
Receipt: `docs/largefile-task-receipts/R09-tflite-vtable-boundary-2026-09-11.md`.

R01 task-receipt provenance exclusion (2026-09-11 UTC): task receipts are now
excluded from the Git-mode source manifest as external run metadata, alongside
the generated dashboard and coordinator ledger. The isolated Git regression
passed 13/13 and proved receipt edits do not change the source identity while
executable and untracked source edits still do. The complete source/evidence
guard sweep passed, the post-change source-manifest SHA-256 was
`c7c8baa7616f7e990ffc41763c92d6ebbd287ced505f8da1735a12a91f323e12`, and no
capability was promoted. Release qualification remains blocked; certified
runner/build and full-size evidence are still required.
Receipt: `docs/largefile-task-receipts/R01-task-receipt-provenance-2026-09-11.md`.

R02/R10 service resource-evidence hardening (2026-09-11 UTC): the service
producer now retains RSS/temp sample counts and measured service, milter,
parallel-client, and temporary-space peaks; the independent post-run checker
requires those canonical fields, positive samples, the fixed 64-GiB temporary
budget, and peak-versus-budget comparisons. It also rechecks retained
parallel-client and milter elapsed times against the retained latency budget.
Checksum-refreshed tamper regressions for RSS, temporary-space, and elapsed
time pass. The focused service evidence suite passes, the full tools suite
remains 147 passed with 2 expected Linux filesystem skips, the complete
source/evidence guard is green, and the current source-manifest SHA-256 is
`ae8307730da2dedcf28359186164eaedf199de9cc45853e9ec168548b40c90f3` across
1,678 entries. No capability was promoted; certified x86-64, full-size,
sanitizer, privileged, and R04 qualification evidence remain open.
Receipt: `docs/largefile-task-receipts/R02-service-resource-evidence-2026-09-11.md`.

R06 OneNote reader cleanup (2026-09-11 UTC): the bounded legacy
reader-backed OneNote path now invokes sink abort cleanup when sink begin
fails, and a regression covers that lifecycle contract. The disposable
current-source parser profile passed check and 61/61 parser tests; the
disposable current-source OneNote consumer profile passed 21/21 tests. The
host tools suite passed 147 tests with 2 expected skips, the complete
source/evidence guard passed all 597 capability bindings, and snapshot,
inventory, and diff checks passed. The host Rust toolchain lacks rustfmt, so
no installation was attempted. No capability was promoted; certified x86-64,
full-size, sanitizer, privileged, production-service, and R04 qualification
evidence remain open. Release readiness remains blocked. Receipt:
`docs/largefile-task-receipts/R06-onenote-reader-cleanup-2026-09-11.md`.

R10 structured-report version binding (2026-09-11 UTC): numeric verdicts in
the shared structured clamd report consumer now require integer report
`version: 1`; missing or unsupported numeric versions fail closed while the
documented versionless string-valued incomplete compatibility path remains
unchanged. The focused acceptance/status tests passed 25/25, the host tools
suite passed 147 tests with 2 expected skips, the complete source/evidence
guard passed all 597 capability bindings, and snapshot, inventory, and diff
checks passed. The retained CMake binary predates this edit and the available
container lacks JSON-C development headers, so no linked C runtime result was
claimed. No capability was promoted; certified x86-64, full-size, sanitizer,
privileged, production-service, and R04 qualification evidence remain open.
Release readiness remains blocked. Receipt:
`docs/largefile-task-receipts/R10-structured-report-version-2026-09-11.md`.

R04 strict resource-phase grammar (2026-09-11 UTC): acceptance records now
parse the complete semicolon-delimited resource-phase field and reject
unknown, empty, or duplicate measured/development tokens instead of silently
ignoring extra text. The focused acceptance/producer/development-service
suite passed 26/26, the full source/evidence guard passed all 597 capability
bindings, and snapshot, inventory, and diff checks passed. The C structured-
report regression literals were also corrected to valid escaped C strings;
the retained binary predates the source edits and JSON-C headers remain
unavailable, so no linked C result is claimed. No capability was promoted;
certified x86-64, full-size, sanitizer, privileged, production-service, and
R04 acceptance evidence remain open. Receipt:
`docs/largefile-task-receipts/R04-resource-phase-grammar-2026-09-11.md`.

R09 TFLite vtable regression (2026-09-11 UTC): the TFLite vtable-distance
hardening is now bound to the required AI-model C test group. The new public
scan regressions cover zero and UINT32_MAX distances and require CL_EPARSE,
cleared verdict/alert state, and non-cacheability. The host tools suite passed
147 tests with 2 expected skips, the complete source/evidence guard passed all
597 capability bindings, and snapshot, inventory, and diff checks passed. The
new C test could not be linked because the retained binary predates the edit
and the available Docker images lack JSON-C/Zlib test headers. No capability
was promoted; certified x86-64, full-size, sanitizer, production-service,
and R04 acceptance evidence remain open. Receipt:
`docs/largefile-task-receipts/R09-tflite-vtable-test-2026-09-11.md`.

R09 TFLite buffer-vector bounds (2026-09-11 UTC): the recognized TFLite
Model `buffers` vector now validates each present `Buffer.data` scalar byte
vector through the bounded FlatBuffer reader, rejecting out-of-range offsets
as incomplete and non-cacheable instead of treating payload ranges as opaque.
The required AI-model test group includes the public API regression for an
out-of-range UINT32_MAX data offset. The host tools suite and complete
source/evidence guard pass, with 597 capability bindings and fresh snapshot,
inventory, and diff checks. The new C test is source-registered but not linked
here because the retained binary predates the edit and the available Docker
images lack JSON-C/Zlib development headers. No capability was promoted;
certified Linux x86-64, full-size, sanitizer, production-service, R04
acceptance, and full TFLite semantic evidence remain open. Receipt:
`docs/largefile-task-receipts/R09-tflite-buffer-vector-2026-09-11.md`.

R09 TFLite tensor/operator semantic bindings (2026-09-11 UTC): the bounded
FlatBuffer walk now follows recognized `OperatorCode`, `SubGraph`, `Tensor`,
and `Operator` tables, validates signed shape dimensions and rank, bounds
TensorType values, binds tensor buffer indices to Model buffers, and binds
operator opcode/input/output references to their declared vectors. The public
AI-model tests include a valid one-tensor/one-operator control plus fail-
visible invalid TensorType, tensor-buffer, opcode, input, and output
references. The host
tools suite passed 147 tests with 2 expected skips; the 597-row source guard,
snapshot, inventory, and diff checks passed. A disposable C syntax probe
remained blocked by the image's missing JSON-C development header, so no
linked result or capability promotion is claimed; an isolated current-source
C parser harness independently passed all 6 valid/malformed cases. Certified Linux x86-64,
sanitizer, full-size, production-service, and complete TFLite semantic
qualification remain open. Receipt:
`docs/largefile-task-receipts/R09-tflite-tensor-operator-semantics-2026-09-11.md`.

R09 TFLite signed OperatorCode version (2026-09-11 UTC): the bounded
FlatBuffer semantic walk now rejects zero and out-of-range signed
`OperatorCode.version` values, closing the negative-`int32` admission gap.
The public API regression mutates the version field to `UINT32_MAX`; the
isolated current-source parser harness passes 7/7, including this case. The
host tools suite passed 147 tests with 2 expected skips; source guards passed
with 597 capability bindings; snapshot, regenerated inventory, and diff
checks passed. Current source-manifest SHA-256 is
`42c96cebd6a3fa26eac45037b62bb1b65380c92dd9eccae6f15912ed691ce7e2`.
The linked C build remains unavailable because the disposable image lacks
JSON-C development headers, so no capability was promoted. Certified Linux
x86-64, sanitizer, full-size, production-service, R04 acceptance, and
complete TFLite semantic qualification remain open. Receipt:
`docs/largefile-task-receipts/R09-tflite-operator-version-2026-09-11.md`.

R09 Python marshal `TYPE_STRINGREF` support (2026-09-11 UTC): the bounded
non-executing Python bytecode walker now consumes legal `R` string-reference
objects and requires their indexes to be within the already-accounted marshal
reference table. A registered legacy-layout regression covers a flagged
string followed by `TYPE_STRINGREF`; the host tools suite passed 147 tests
with 2 expected skips, source guards passed with 597 capability bindings, and
snapshot, regenerated inventory, and diff checks passed. Current
source-manifest SHA-256 is
`d9d27ba8c7e7607471021007892f78a07914db276c80d6e586c4ea086361ee21`.
The linked C test remains unavailable because the disposable image lacks
JSON-C development headers, so no capability was promoted. Independent
format-8, certified Linux x86-64, sanitizer, full-size, production-service,
R04 acceptance, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R09-python-stringref-2026-09-11.md`.

R09 Python marshal string-reference table correction (2026-09-11 UTC): the
bounded Python walker now models legacy Python 2 `TYPE_STRINGREF` as an index
into the separate `TYPE_INTERNED` string table, rather than the Python 3
`FLAG_REF` object table. The valid regression now uses a legal `t`/`R` pair and
an additional malformed regression rejects `R 0` without an interned entry.
The parser also rejects `R|FLAG_REF`, which cannot be both a lookup and a new
reference-table entry. The host tools suite passed 147 tests with 2 expected skips; source guards,
snapshot freshness, shell syntax, and diff checks passed. Linked current-source
C execution, certified Release/sanitizer, independent format-8, full-size,
production-service, R04 acceptance, and final release qualification remain
open. Receipt:
`docs/largefile-task-receipts/R09-python-stringref-table-2026-09-11.md`.

R09 Python marshal reference-registration semantics (2026-09-11 UTC): the
bounded Python walker now counts `FLAG_REF` only for marshal types that CPython
actually registers, so flagged singleton values cannot manufacture a later
valid `TYPE_REF` target. A malformed regression covers `FLAG_REF` on `None`;
the host tools suite passed 147 tests with 2 expected skips, and source guards,
snapshot freshness, shell syntax, inventory, and diff checks passed. Linked C,
certified Release/sanitizer, independent format-8, full-size,
production-service, R04 acceptance, and final release qualification remain
open. Receipt:
`docs/largefile-task-receipts/R09-python-marshal-reference-semantics-2026-09-11.md`.

R10 milter framed-reply and indefinite-timeout semantics (2026-09-11 UTC):
the structured milter consumer now rejects a second JSON report frame after
the one authoritative report, and `ReadTimeout=0` now correctly blocks
indefinitely instead of failing before the first `select()`. The host tools
suite passed 147 tests with 2 expected skips; source guards passed with 597
capability bindings; snapshot, regenerated inventory, manifest, and diff
checks passed. Current source-manifest SHA-256 is
`bff47fe203f641e0a094c4bbfb66ef835723d64d1904e3cc223b317c31da29f6`.
The linked current-source C runtime remains unavailable because the retained
build predates the edit and the available Docker images lack JSON-C and Check
development headers. No capability was promoted; certified Linux x86-64,
full-size, sanitizer, privileged, production-service, R04 acceptance, and
final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R10-milter-framed-reply-timeout-2026-09-11.md`.

R10 nonblocking milter descriptor send (2026-09-11 UTC): `nc_sendmsg()` now
retries interrupted or temporarily unwritable nonblocking sends within the
existing 30-second budget, rejects short successful sends, and fails closed
on timeout or wait errors while passing `SCM_RIGHTS`. The host tools suite
passed 147 tests with 2 expected skips; source guards passed with 597
capability bindings; snapshot, regenerated inventory, manifest, and diff
checks passed. Current source-manifest SHA-256 is
`4ec4f450396d56a5ba56183daf0e2a4c666e9c0889c4ee08f753f4cf4d46837f`.
The linked current-source C runtime remains unavailable because the retained
build predates the edit and the available Docker images lack JSON-C and Check
development headers. No capability was promoted; certified Linux x86-64,
full-size, sanitizer, privileged, production-service, R04 acceptance, and
final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R10-milter-fd-send-2026-09-11.md`.

R09 AI-model backing-read status (2026-09-11 UTC): the bounded
`CL_TYPE_AI_MODEL` reader now preserves an in-range fmap backing-read failure
as `CL_EREAD` with sticky incomplete/non-cacheable state, while retaining
`CL_EPARSE` for a short/truncated read. The injected-fmap regression is
registered in the ordinary and required-unsupported cases; host tests passed
147 tests with 2 expected skips, source guards passed with 597 capability
bindings, and snapshot, regenerated inventory, manifest, and diff checks
passed. Current source-manifest SHA-256 is
`493b07b798b0ad97cc7425819fb6face2e2ceb46eba8833751fecdece1af13b2`.
The linked current-source C runtime remains unavailable because the retained
build predates the edit and the available Docker images lack JSON-C and Check
development headers. No capability was promoted; full AI-model parser
semantics, certified Linux x86-64, full-size, sanitizer, privileged,
production-service, R04 acceptance, and final release qualification remain
open. Receipt:
`docs/largefile-task-receipts/R09-ai-model-read-status-2026-09-11.md`.

R10 on-access descriptor reply timeout (2026-09-11 UTC): the descriptor-backed
on-access reply reader now waits under the configured timeout before blocking
`recv()`, preserves timeout versus receive-error status, and classifies signed
`recv()` results before assigning the successful count to its unsigned buffer
length. The existing Docker toolchain syntax check passed warning-free; host
tests passed 147 tests with 2 expected skips; source guards passed with 597
capability bindings; snapshot, regenerated inventory, manifest, and diff
checks passed. Current source-manifest SHA-256 is
`133ccef558ef5cb9df05ab884e4516c49a8f9867d25f260088230eba7a9ac3aa`.
No current-source linked runtime or capability promotion was claimed because
the available images lack JSON-C and Check development headers. Certified
Linux x86-64, sanitizer, privileged on-access execution, full-size service
parity, R04 acceptance, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R10-onaccess-fd-reply-timeout-2026-09-11.md`.

R09 Python marshal backing-read status (2026-09-11 UTC): the bounded Python
reader now preserves an in-range fmap backing-read failure as `CL_EREAD` with
sticky incomplete/non-cacheable state, while short/truncated marshal input
remains `CL_EPARSE`. The public regression is registered in both ordinary and
required-unsupported groups; host tests passed 147 with 2 expected skips, the
source guard passed with 597 capability bindings, and refreshed
inventory/snapshot checks passed. Current source-manifest SHA-256 is
`a7cf950670932058e077cf81706fe4fef93a16730d124312527f8650870f4b97`.
No linked current-source C execution or capability promotion was claimed
because the available images lack JSON-C and Check development headers.
Certified Linux x86-64, sanitizer, production-CVD/service, full-size, R04
acceptance, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R09-python-read-status-2026-09-11.md`.

R10 on-access timeout normalization (2026-09-11 UTC): curl-backed on-access
send and receive waits now normalize signed timeout values before the unsigned
socket-wait helper, and curl-backed receive readiness failures preserve
`CURLE_RECV_ERROR`. The descriptor-backed reader retains the same normalized
timeout boundary. Host tests passed 147 with 2 expected skips; source guards
passed with 597 capability bindings, refreshed inventory/snapshot and
acceptance checks passed, and the current source-manifest SHA-256 is
`5183c325e03e21e3fd09e6f01723d4a1bc100104484857198fd3971daccaed94`.
Current-source linked execution, certified x86-64, full-size, sanitizer,
privileged, production-service, R04 acceptance, and final release
qualification remain open. Receipt:
`docs/largefile-task-receipts/R10-onaccess-timeout-normalization-2026-09-11.md`.

R10 shared command-send width hardening (2026-09-11 UTC): `sendln()` now
stores the native `ssize_t` result from `send()` while draining its bounded
unsigned wire-length input, preventing a large successful write from being
misclassified through an `int` narrowing conversion. Source and host controls
remain the verification basis; linked current-source runtime, certified
x86-64, full-size service parity, and final release qualification remain open.

R10 milter send deadline and spool-write retry (2026-09-11 UTC): `nc_send()`
now establishes one deadline for a complete nonblocking payload instead of
resetting the deadline after each partial write, and the local milter temp-file
spool retries `EINTR` without abandoning the message. Source and host controls
remain the verification basis; linked current-source milter execution,
certified x86-64, full-size service parity, and final release qualification
remain open. The stable current source-manifest SHA-256 is
`2e00bba6b8dadca33d8d5e17eca3679018ca48c37215ab4ab8d5ac1dcc98429a`.
Receipt:
`docs/largefile-task-receipts/R10-milter-send-deadline-spool-write-2026-09-11.md`.

R10 current-source ingress syntax verification (2026-09-11 UTC): ten changed
shared/service/client translation units passed disposable Docker C syntax
checks with warnings treated as errors, including milter netcode, clamd
communication/session/scanner, clamdscan, on-access communication/protocol,
common actions, and milter quota. JSON-C was represented only by a temporary
type stub because the image lacks its development header; no linked-runtime
or qualification claim follows. Receipt:
`docs/largefile-task-receipts/R10-current-source-syntax-2026-09-11.md`.

The corrected source-manifest SHA-256 is
`cd5a9c391c706e45b9b7f9bc58d908b39a85e6e32c8bd403187bcb9349467eeb`;
host tests, source guards, inventory freshness, snapshot validation, and
syntax checking remain green.

R06 modern-reader boundary verification (2026-09-11 UTC): a temporary
out-of-tree manifest compiled the current vendored OneNote parser offline;
61/61 library tests and 2/2 reader-boundary tests passed, including short
reads and a logical `256 MiB + 1` input. The regular package test remains
blocked by the uncached offline `insta` dev dependency. No capability was
promoted. Receipt:
`docs/largefile-task-receipts/R06-modern-onenote.md`.

R10 milter compile correction (2026-09-11 UTC): restored the `nc_send()` local
scratch buffer required by the shared `strerror_print` macro after the send
deadline hardening exposed a compile defect. A disposable Docker toolchain
passed warning-free syntax checking for `clamav-milter/netcode.c`, and a
source guard binds the buffer to the error branch. No capability was promoted.
Receipt:
`docs/largefile-task-receipts/R10-milter-send-deadline-spool-write-2026-09-11.md`.

R10 milter deadline enforcement (2026-09-11 UTC): `nc_send()` now enforces its
single end-to-end deadline before every nonblocking `send()`, including the
repeated-successful-partial-write path that never reaches `EAGAIN`. The ten
changed ingress translation units pass disposable warning-as-error syntax
checks; host tooling passes 147 tests with 2 expected skips; source guards,
inventory freshness, snapshot validation, and `git diff --check` remain green.
Refreshed source-manifest SHA-256:
`7367697b6324da35cfa800e0f42c280b208f8ed9e6266e1b943411b907d935f7`.
No capability was promoted. Receipt:
`docs/largefile-task-receipts/R10-milter-send-deadline-spool-write-2026-09-11.md`.

R10 milter guard precision (2026-09-11 UTC): the deadline guards now require
pre-send checks before the actual `send()` and `sendmsg()` calls, preventing
the existing readiness-wait check from masking removal of the new enforcement.
The guard sweep, host suite (147 passed, 2 expected skips), focused syntax
check, inventory/snapshot validation, and `git diff --check` passed. Refreshed
source-manifest SHA-256:
`07b9f9b1f92a71c9b361f004de4b3c5e0de413821231a3d4c4bb2adada8ce4d8`.
No capability was promoted. Receipt:
`docs/largefile-task-receipts/R10-milter-send-deadline-spool-write-2026-09-11.md`.

R10 milter FD-passing deadline enforcement (2026-09-11 UTC): `nc_sendmsg()`
now enforces its single end-to-end deadline before every `sendmsg()` retry,
including repeated `EINTR` retries that bypass the readiness wait. The focused
warning-as-error milter syntax check passed; host tooling passed 147 tests with
2 expected skips; source guards, inventory freshness, snapshot validation, and
`git diff --check` remain green. Refreshed source-manifest SHA-256:
`77146a74752dec7e1bc49b30d32af4193ca46a86c92ff3a9df905690aab3981b`.
No capability was promoted. Receipt:
`docs/largefile-task-receipts/R10-milter-send-deadline-spool-write-2026-09-11.md`.

R10 on-access FD-pass timeout parity (2026-09-11 UTC): the local FILDES
socket is nonblocking, in-progress connect is bounded by OnAccessCurlTimeout,
and command plus SCM_RIGHTS sends preserve one deadline with distinct timeout
and write statuses. Focused Docker syntax checks passed with warnings treated
as errors; host tooling passed 147 tests with 2 expected skips; source guards,
focused protocol/service controls, inventory, snapshots, acceptance map, and
`git diff --check` passed. Two consecutive source-manifest generations matched
at `1f16a6014a02be9857f41866926c15c39db282459d69baa9aaa3eb65923e4160`.
No capability was promoted. Certified x86-64, full-size ingress/on-access
service evidence, R03 runner qualification, R04 records, sanitizer, and final
release qualification remain open. Receipt:
`docs/largefile-task-receipts/R10-onaccess-fdpass-timeout-2026-09-11.md`.

R10 on-access FD-pass transport hardening (2026-09-11 UTC): connect and
writable-send waits rebuild their select state and remaining deadline after
`EINTR`, and raw FILDES command/SCM_RIGHTS sends suppress `SIGPIPE` with the
platform-supported socket/send flags. Focused warning-as-error syntax, host
tests (147 passed, 2 expected skips), source guards, inventory/snapshots, and
`git diff --check` passed. Current source-manifest SHA-256:
`3a29e00559104dd7328e4bd8e1bd264c38fc7f2e238cb3aafa2332433773a119`.
No capability was promoted. Receipt:
`docs/largefile-task-receipts/R10-onaccess-fdpass-timeout-2026-09-11.md`.

R10 on-access curl readiness EINTR deadline (2026-09-11 UTC):
`onas_socket_wait()` now rebuilds its select state and remaining timeout from
one absolute `OnAccessCurlTimeout` deadline after each interrupted wait. The
affected C ingress units pass warning-as-error syntax checks; the host tools
suite passes 147 tests with 2 expected skips; focused protocol/service tests,
the complete source-guard sweep, refreshed inventory, and `git diff --check`
pass. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R10-onaccess-curl-eintr-deadline-2026-09-11.md`.

R09 TFLite TensorType boundary (2026-09-11 UTC): the bounded TFLite validator
now rejects undefined `TensorType` values above the current schema maximum of
22 instead of accepting values through 31. A registered required-unsupported
regression mutates a valid tensor/operator model to value 23 and requires
`CL_EPARSE`, no alert, and non-cacheability. The current-source scanner syntax
check passed with warnings treated as errors; host tools passed 147 tests with
2 expected skips; service workload checks passed 28 tests with 2 expected
Linux-only skips; source guards, the 597-row map, refreshed inventory, stable
manifest, and `git diff --check` passed. No capability was promoted. The
current-source linked C test binary, certified x86-64, sanitizer, production
service, full-size model corpus, R04 records, and final release qualification
remain open. Receipt:
`docs/largefile-task-receipts/R09-tflite-tensortype-boundary-2026-09-11.md`.

R06 reference-stream short-input handling (2026-09-11 UTC): embedded-ink and
note-tag adapters now reject declared object/object-space reference ranges
that exceed their backing streams instead of silently truncating them with
`saturating_sub().min()`. The current-source parser harness passed 62/62 and
the consumer harness passed 21/21; host tooling passed 147 tests with 2
expected skips, service workload checks passed 28 tests with 2 expected
Linux-only skips, and inventory, snapshot, acceptance-map/schema, targeted
source assertions, and `git diff --check` passed. No capability was promoted;
certified, full-size, production-service, R04-record, and final release
qualification remain open. Receipt:
`docs/largefile-task-receipts/R06-reference-stream-short-input-2026-09-11.md`.

R06 OneStore/reference-pairing validation (2026-09-11 UTC): object mapping now
validates context and object-space reference stream lengths independently and
requires exact object-reference count parity, rejecting swapped counts and
surplus object IDs that the prior zip-based mapping could silently accept or
discard. Rich-text parsing also rejects embedded text-run data without a
corresponding style entry while preserving valid text-only runs. The
current-source parser harness passed 69/69, and the bundled valid section
sample parsed successfully through the production parser source. Host tooling
passed 147 tests with 2 expected skips; service workload checks passed 28 tests
with 2 expected Linux-only skips; acceptance map/schema, release-readiness
policy tests, inventory freshness, targeted source assertions, and
`git diff --check` passed.
The monolithic source-guard wrapper was stopped after it exceeded the bounded
local run without output and is not claimed as passed. No capability was
promoted; certified, sanitizer, full-size, production-service, R03-runner,
R04-record, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R06-reference-stream-kind-2026-09-11.md`.

R06 OneNote page-content extraction walker (2026-09-11 UTC): the shared
OneNote extraction walker now visits embedded files represented directly as
page contents, and the compatibility iterator reuses that walker instead of
maintaining an outline-only duplicate. The current-source OneNote host
harness passed 21/21; the bundled sample parsed successfully but contains no
embedded-file fixture. Host tooling passed 147 tests with 2 expected skips;
service workload checks passed 28 tests with 2 expected Linux-only skips; the
597-row acceptance map/schema, snapshot, inventory, targeted guards, and
`git diff --check` passed. Full consumer checking remains blocked before
compilation by the offline `clam-sigutil` tag reference. No capability was
promoted; certified, sanitizer, full-size, production-service, R03-runner,
R04-record, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R06-page-content-walker-2026-09-11.md`.

R06 OneNote recursive outline walker (2026-09-11 UTC): extraction now follows
the complete parsed outline tree, including `OutlineItem::Group` and nested
`OutlineElement::children()`, so embedded files below groups or child
elements reach both scanner and compatibility APIs. The current-source
OneNote host harness passed 21/21; host tooling and service workload evidence
from the preceding walker slice remained green at 147/2 expected skips and
28/2 expected Linux-only skips. Acceptance map/schema, snapshot, inventory,
targeted guards, and `git diff --check` passed. No capability was promoted;
certified, sanitizer, full-size, production-service, R03-runner, R04-record,
and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R06-outline-walker-2026-09-11.md`.

R06 OneNote complete content walker (2026-09-11 UTC): the shared extraction
walker now also visits page-title outlines and table rows/cells, in addition
to page-level files, outline groups, and child elements. This closes concrete
parsed-content omissions without changing the scanner/compatibility callback
contract. The current-source OneNote harness passed 21/21; host tooling passed
147 tests with 2 expected skips; service workload checks passed 28 tests with
2 expected Linux-only skips; acceptance map/schema, snapshot, refreshed
inventory, targeted guards, shell syntax, and `git diff --check` passed. No
capability was promoted; certified, sanitizer, full-size, production-service,
R03-runner, R04-record, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R06-complete-content-walker-2026-09-11.md`.

R09 GGUF empty metadata-array element type (2026-09-11 UTC): the GGUF
structural walker now validates an array's declared element type before
iterating its elements, so an undefined type in a zero-count array cannot
become a clean result. The required-unsupported regression
`test_ai_model_gguf_empty_metadata_array_type_is_fail_visible` requires
`CL_EPARSE`, no alert, and non-cacheability. Current-source linked C execution
is not available in this environment; no capability was promoted and
certified, sanitizer, full-size, production-service, R04-record, and final
release qualification remain open. Receipt:
`docs/largefile-task-receipts/R09-gguf-empty-array-type-2026-09-11.md`.

R06 reader-backed OneNote blob streaming (2026-09-11 UTC): stream-backed
FSSHTTPB `ObjectDataBlob` values now use private temporary-file storage in
bounded 64 KiB reader windows and expose a reader to the scanner-facing
attachment walker, avoiding a second whole-payload `Vec<u8>` before ClamAV
temporary-spool scanning. The parser's current-source unit profile passed
70/70, the current-source consumer harness passed 21/21, host tooling passed
147 tests with 2 expected skips, service workload checks passed 28 tests with 2
expected Linux-only skips, and acceptance/schema, shell-syntax, and diff
checks passed. The regular package check remains blocked before compilation by
the uncached offline `insta` dev dependency; full current C/Rust consumer
compilation remains blocked by the missing `openssl/ssl.h` header. No
capability was promoted; certified, sanitizer, full-size, production-service,
Sonic1, R04-record, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R06-reader-backed-blob-stream-2026-09-11.md`.

R06 OneStore object-group data-size validation (2026-09-11 UTC): the modern
OneNote parser now requires each inline or excluded object group's data size to
match its declaration, preventing malformed object metadata from being
accepted with a mismatched payload. The current-source parser unit profile
passed 72/72, including focused mismatch and excluded-object coverage;
targeted source guards and shell syntax checks passed. No capability was
promoted; certified, sanitizer, full-size, production-service, Sonic1,
R04-record, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R06-object-group-size-validation-2026-09-11.md`.

R03 Sonic1 current-source build (2026-09-11 UTC): the checksum-verified
current checkout configured and built successfully on the available Linux
x86-64 Docker environment with workflow-equivalent static and roadmap test
flags enabled. The resulting `clamscan` reported
`ClamAV 1.5.3-largefile-devel`; a repository-HDB clean scan returned `OK`,
and a temporary NDB signature produced the expected detection exit 1. The
static-linked `check_clamav` target then passed focused `required_unsupported`
(47), OneNote (2 + 2 Rust consumer), CryptFF (3), and GIF/fuzzy-image (16)
cases. The image initially lacked the locked `clam-sigutil` Git source, so
the dependency set was fetched into a persistent remote cache; the build then
completed offline. This is development evidence only: no certified runner,
sanitizer, full-size 32-GiB, production-CVD, daemon/service, or final-canary
evidence was established. No capability was promoted and release readiness
remains blocked. Receipt:
`docs/largefile-task-receipts/R03-sonic1-current-source-build-2026-09-11.md`.

R06 OneNote parser offline verification (2026-09-11 UTC): the current
checksum-verified Sonic1 source was tested in a named x86-64 Docker container
with the retained offline Cargo cache. `cargo test --offline --all-targets`
exited 0 with 72 unit tests and 5 integration tests, including the reader
path's logical-input-above-former-cap and short-read parity cases. The Docker
image used stable Rust 1.97.1; no Rust address instrumentation, certified
runner, materialized-large-file, production-CVD/service, R04-record, or final
release evidence was claimed. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R06-onenote-parser-offline-2026-09-11.md`.

R03 Sonic1 CTest control revalidation (2026-09-11 UTC): repaired three
control-contract issues found by the first targeted CTest run. The runtime
evidence verifier now has a bounded Python ELF header fallback for minimal
containers without `file`; the clamscan admission fixture explicitly disables
AlertExceedsMax to assert the operational exit-2 limit result; and the exact
32-GiB Check case now binds the repository's established `*_ex2` strong
indicator/report status and has a 900-second default for its three sparse
passes. The two quick controls passed 2/2, and the configured exact CTest
control passed 1/1 in 346.02 seconds. Final static Check binary:
`fc7fd546c89c55a4ced07e061eaa645e999adeb5009fafa2e9cfa91bce419f69`. No
capability was promoted; certified-runner, sanitizer, production-service,
R04-record, and final-canary evidence remain open. Receipt:
`docs/largefile-task-receipts/R03-sonic1-current-source-build-2026-09-11.md`.

R05 Sonic1 current-source oversize FILDESREPORT revalidation (2026-09-11
UTC): current-source `clamd` and `clamscan` targets built successfully and the
exact sparse 32-GiB+1 descriptor was exercised through `FILDESREPORT` with
`MaxFileSize=32G` and `MaxScanSize=64G`. Both alerts-off and alerts-on runs
passed the exact pre/post PONG and cleanup controls with zero allocated,
parser, matcher, logical, and temporary work. Alerts off returned
`LIMIT_INCOMPLETE`/`CL_EMAXSIZE`; alerts on returned
`DETECTION_TERMINATED` with the exact `Heuristics.Limits.Exceeded.MaxFileSize`
alert. Bundle SHA-256:
`c86af2c4164d46219c52ad426b4c52ad0700dc9a0c70c66b619907b92cbc516a`.
Development evidence only; certified-runner reproduction, full materialized
release fixtures, R04 records, and final qualification remain open. No
capability was promoted. Receipt:
`docs/largefile-task-receipts/R05-fixture-oracle.md`.

R03 Sonic1 static test-link and scan-API revalidation (2026-09-11 UTC): the
complete encrypted-fixture aggregate was materialized (53 expected inputs),
then the current Check target was corrected to avoid the shared `libclamav`
path and to bind the static UnRAR implementation. The large scan-API group
also received a truthful 60-second default timeout while preserving its `T`
override. The final static binary passed `cl_scan_api` 836/836 with zero
failures/errors, including encrypted RAR and MHTML streaming coverage;
`required_unsupported` passed 47/47; OneNote passed 2/2 plus Rust consumer
2/2; CryptFF passed 3/3; and GIF passed 16/16. No capability was promoted;
certified, sanitizer, full-size, production-service, R04-record, and final
release qualification remain open. Receipt:
`docs/largefile-task-receipts/R03-sonic1-current-source-build-2026-09-11.md`.

R03 Sonic1 full current-source Check-suite revalidation (2026-09-11 UTC): the
AutoIt fixtures were materialized and the rebuilt static `check_clamav` suite
was run with the CMake test trust store at
`/candidate/unit_tests/input/signing/verify`. The corrected run completed
`cl_suite` with 2,889 checks, 0 failures, and 0 errors, including the strict
malformed-CVD archive case and the previously slow PDF/API cases. An earlier
one-failure result used `/candidate/certs`, which is not the unit-test signing
store; it was discarded as harness setup evidence. No capability was
promoted; certified, sanitizer, full-size, production-service, R04-record, and
final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R03-sonic1-current-source-build-2026-09-11.md`.

Repository consistency revalidation (2026-09-11 UTC): aligned two stale
OneNote source-guard tokens with the current reader-backed implementation,
refreshed the generated large-file inventory, and passed the full
`tools/largefile_source_guards.sh` sweep. The sweep covered all 597 capability
entries plus release-readiness, acceptance-record, snapshot/PDF evidence, and
schema checks. The snapshot freshness check, 13 snapshot unit tests, shell
syntax checks, and `git diff --check` also passed. No capability was promoted;
release readiness remains blocked pending certified, full-size,
production-service, and final-canary evidence. Receipt:
`docs/largefile-task-receipts/R03-sonic1-current-source-build-2026-09-11.md`.

R03 Sonic1 fresh C ASan/UBSan revalidation (2026-09-11 UTC): the isolated
`RelWithDebInfo` sanitizer build completed with exit 0 and produced scanner,
daemon, client, and native test artifacts with both sanitizer runtimes linked.
ASan found an uninitialized `tc_largefile` test-harness pointer during the
first run; initializing it to `NULL` fixed the pre-test crash. The runner then
restored the exact tracked HDB fixture at the CMake-embedded `/src` path and
materialized the three AutoIt fixtures. Focused controls passed `cl_api` 518/518,
`autoit_map` 9/9, and `autoit_corpus` 1/1. The configured sanitizer CTest
entry passed 1/1 in 132.17 seconds with no ASan/UBSan diagnostic. Remote tested
source hash was `4a81f43c0caf099034398171ec731e969801c4a69e387820dcdc1a48f855fb36`;
current local working-tree test-source hash was
`307b81d2e00225ef60bceb4041dfa4536598136974ec8561f3aa90cf8294ea6b`, so this
remains disposable development evidence rather than revision-bound final
qualification. Rust address instrumentation, certified/full-size/production
evidence, R04 records, and final canary remain open. No capability was
promoted. Receipt:
`docs/largefile-task-receipts/R03-sonic1-current-source-build-2026-09-11.md`.

R06 private OneNote reader-spool hardening (2026-09-11 UTC): stream-backed
object-data spools now request owner-only `0600` permissions on Unix, and the
reader unit profile adds partial-spool cleanup and permission regressions.
`git diff --check` and the source-guard syntax check passed. Local offline
Cargo execution remains blocked by the uncached `insta` dev dependency; the
updated private source was not exported to Sonic1 after MCP-SSH rejected that
destination as unauthorized. No capability was promoted; linked runtime,
certified, full-size, production-service, R04-record, and final release
qualification remain open. Receipt:
`docs/largefile-task-receipts/R06-reader-spool-private-2026-09-11.md`.

R06 zero-length OneNote reader-blob admission (2026-09-11 UTC): a declared
zero-byte stream-backed object now stays in memory as an empty value instead
of creating and immediately deleting a disk spool. The reader regression
asserts the no-spool representation under the existing serialized temp-file
profile, and the source guard pins the branch. No capability was promoted;
full crate, linked runtime, sanitizer, certified, full-size, production-
service, R04-record, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R06-reader-zero-blob-2026-09-11.md`.

R09 fuzzy-image null-context status admission (2026-09-11 UTC): the
reader-backed image fuzzy-hash FFI now maps its explicit null scan-context
error to `CL_ENULLARG` instead of the generic parse status. A focused Rust
regression pins the mapping, preserving the distinction between invalid API
arguments and malformed image input. No capability was promoted; full crate,
linked current-source execution, sanitizer, certified, full-size,
production-service, R04-record, and final release qualification remain open.
Receipt:
`docs/largefile-task-receipts/R09-fuzzy-image-null-context-2026-09-11.md`.

R09 ONNX TensorProto enum boundaries (2026-09-11 UTC): the structural ONNX
walker now rejects out-of-range `data_type` and `data_location` enum values
instead of treating valid protobuf varints as a complete recognized model. A
valid current upper-bound case and two fail-visible invalid-enum cases are
registered in both ordinary and required-unsupported development groups.
Source guards and snapshot/inventory consistency checks passed; linked C
execution remains pending because this host lacks Docker access and the
OpenSSL development header. No capability was promoted; certified, sanitizer,
full-size, production-service, R04-record, and final release qualification
remain open. Receipt:
`docs/largefile-task-receipts/R09-onnx-enum-boundaries-2026-09-11.md`.

R09 ONNX AttributeProto boundaries (2026-09-11 UTC): the structural ONNX
walker now requires an attribute name and rejects an out-of-range
`AttributeProto.type` discriminator instead of treating valid protobuf wire
types as a complete nested attribute. A valid named/typed case and two
fail-visible semantic-boundary cases are registered in both ordinary and
required-unsupported development groups. The host suite passed 147 tests with
2 expected skips; the full source-guard, snapshot, inventory, shell-syntax,
and diff checks passed. A current-source ARM64 Docker build then linked the
test and application binaries; `cl_suite/required_unsupported` passed 56/56,
`cl_suite/cl_api` passed 519/519, and CTest passed `libclamav`, `clamscan`,
and `sigtool` 3/3. The configured large-file CTest controls also passed 8/8.
This is development evidence only: the container is not the certified Linux
x86-64 profile and large-file defaults were disabled. No capability was
promoted; certified, sanitizer, full-size, production-service, R04-record,
and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R09-onnx-attribute-boundaries-2026-09-11.md`.

R09 ONNX TensorProto required data type (2026-09-11 UTC): the structural
ONNX walker now rejects a TensorProto that omits its required `data_type`
field, and a fail-visible empty-tensor fixture is registered in both ordinary
and required-unsupported development groups. The current-source ARM64 Docker
build completed at 100%; linked `cl_suite/required_unsupported` passed 57/57,
`cl_suite/cl_api` passed 520/520, and the updated CTest integration/control
selection passed 11/11. Source guards, regenerated inventory, snapshot,
syntax, and diff checks passed. This remains development evidence only, with
large-file defaults disabled on a non-certified architecture; no capability
was promoted and certified, full-size, production-service, R04-record, and
final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R09-onnx-tensor-required-field-2026-09-11.md`.

R06 modern OneNote reader-over-cap admission (2026-09-11 UTC): the current
production `scan_onenote()` path was exercised against the valid modern
`New Section 1.one` sample through a bounded fmap callback with a logical
length of 256 MiB plus one byte. The linked ARM64 Docker `rust_onenote` suite
passed 3/3, including this reader-over-former-cap case, and the updated CTest
integration/control selection passed 11/11 after inventory regeneration. The
test does not allocate or read the zero-filled tail and asserts clean,
cacheable completion. The complete current CTest matrix subsequently passed
15/15, including the Rust package, `clamd`, and `freshclam` targets. This is
development evidence only: materialized
late-child/offset evidence, certified Linux x86-64, sanitizer, full-size,
production-service, Sonic1, and final release qualification remain open; no
capability was promoted. Receipt:
`docs/largefile-task-receipts/R06-modern-onenote-reader-over-cap-2026-09-11.md`.

R03 Rust sanitizer CTest runner (2026-09-12 UTC): the current-source ARM64
sanitizer build exposed that Cargo's Rust test executable needs the
compiler-selected ASan/UBSan runtimes preloaded, while Cargo and rustc must
not inherit that preload. `cmake/FindRust.cmake` now derives the actual target
name and runtime paths and supplies a target-specific Cargo runner. The direct
sanitized Rust unit-test binary passed 159/159, the reader-backed OneNote
sanitizer case passed 3/3, and the corrected `libclamav_rust` CTest target
passed 1/1. A direct run of the complete `cl_suite/cl_api` group then passed
520/520 in 10 minutes 23 seconds; all three action-source tests passed under
sanitizers, and the `traverse_to: Failed open payload` text was the expected
replaced-symlink diagnostic. The broader selected sanitizer CTest timeout is
therefore not an action-test failure. The Python test executor now forwards
keyword arguments correctly, and a restricted `libclamav` CTest invocation
with `CK_RUN_CASE=cl_api` passed 1/1 in 606.66 seconds, completing all 520
checks under the sanitizer-specific 1200-second allowance. The unfiltered
`cl_suite` remains open for a certified runner; this ARM64 development
evidence does not satisfy the nightly Rust, certified x86-64, full-size,
production-service, R04-record, fanotify, or final release gates. Receipt:
`docs/largefile-task-receipts/R03-rust-sanitizer-runner-2026-09-12.md`.

R06 OneNote corpus attachment over-cap reader (2026-09-12 UTC): the linked
current-source ARM64 build now exercises the real attachment-bearing
`clam.exe.2010.one` corpus through a bounded fmap callback with a logical
length of 256 MiB plus one byte. The new production `scan_onenote()` test
uses a two-layer child scan and a private `OneNote.Reader.MZ` signature, so
its 4/4 `rust_onenote` result demonstrates reader-backed extraction and
nested child detection rather than raw container matching. The core normal
application matrix passed 5/5. An unfiltered normal `libclamav` attempt was
blocked by the disposable Docker filesystem during its unrelated large
temporary-fixture writes; the focused OneNote case passed after redirecting
disposable temp output to host-backed storage. Source manifest and diff
checks passed. No capability was promoted; certified x86-64, sanitizer
coverage for this new case, full-size, production-service, R04-record, and
final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R06-reader-corpus-attachment-over-cap-2026-09-12.md`.

R06/R00 normal-suite storage and path portability follow-up (2026-09-12
UTC): the correctly configured current-source ARM64 `libclamav` CTest target
passed 2865 checks with 0 failures and 0 errors using host-backed temporary
storage. The run exposed and fixed a real partial-message spool defect: its
private directory now has owner execute permission. The long-path CVD test
now preserves its >1023-character logical path through a short physical
symlink chain, avoiding the Docker Desktop bind-mount `ENAMETOOLONG` limit
while retaining the path-construction coverage. The current source manifest
is `8c6ad5642f35ea7d8812d4011636fe90db589b9522eb45d74d346bd1f7d70c89`.
No capability was promoted; certified x86-64, sanitizer, full-size,
production-service, R04-record, and final release qualification remain open.
Receipt:
`docs/largefile-task-receipts/R06-reader-corpus-attachment-over-cap-2026-09-12.md`.

R07 independent bytecode format-8 prerequisite audit (2026-09-12 UTC): the
active disposable ARM64 container has GCC but no `clang`, `llvm-as`, or `llc`,
and the repository has no independent format-8 compiler output or `.bc`/`.ll`
fixture. The existing generated `bytecode.cud` is a legacy ClamAV database,
not the required independent format-8 artifact. Per the roadmap, this slice
is explicitly blocked on an authorized compatible compiler or independently
compiled artifact plus source identity/hash; nothing was installed,
downloaded, or externally contacted. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R07-format8-artifact-prerequisite-2026-09-12.md`.

R05 Sonic1 current-source sparse oversized admission (2026-09-16 UTC): after
regenerating the Git-less snapshot inventory and rebinding the Release build,
the current Linux x86-64 `clamd` passed the exact 32-GiB+1 `FILDESREPORT`
probe with both `AlertExceedsMax` modes. Alerts off returned `CL_EMAXSIZE`,
`LIMIT_INCOMPLETE`, and the exact MaxFileSize reason; alerts on returned
`DETECTION_TERMINATED` with the exact MaxFileSize alert. Both reports showed
zero parser, matcher, logical-byte, and temporary work, preserved `PONG`
health before and after, and removed the sparse fixture. The combined report
and its verifier passed with the source/build manifest bound to
`1fce4719f42ed92d5f0a4b8eeebb6db6268cb5981b7251894d950413cce6135f`.
This closes the R05 live sparse admission slice only; it is not materialized
32-GiB, production-CVD, or release qualification evidence. Receipt:
`docs/largefile-task-receipts/R05-sonic1-oversize-admission-current-20260916.md`.

R03 current-host qualification preflight (2026-09-14 UTC): the roadmap
host preflight exited 1 with `host preflight requires Linux x86-64 (found
Darwin/arm64)`. The ARM64 Docker environment remains development-only;
the exact 32-GiB qualification TCase cannot be enabled or claimed here.
R07 also still lacks an independently compiled CBC format-8 artifact or
compatible compiler. No gate was bypassed and no capability was promoted.
Receipt:
`docs/largefile-task-receipts/R03-current-host-preflight-2026-09-14.md`.

R06 OneNote parser temporary-budget integration (2026-09-12 UTC):
stream-backed `ObjectDataBlob` extents now reserve each written 64-KiB reader
window through the shared scan temporary-byte budget and release the exact
reservation when the parser-owned spool drops. The production scanner passes
the current layer's temporary directory into the parser, keeping parser
scratch files under the scan-owned location. The isolated current-source
OneNote parser suite passed 77/77, the linked `rust_onenote` group passed 4/4,
and the full correctly configured normal `libclamav` CTest target passed
2865 checks with 0 failures and 0 errors. Current source manifest:
`9d682db828b0ba68d7ab8a92956e9b11c44dfe2c9879c6b2af9f4399e27af644`.
This remains ARM64 development evidence; no capability was promoted and
certified, sanitizer, full-size late-child, production-service, Sonic1, and
final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R06-reader-corpus-attachment-over-cap-2026-09-12.md`.

R08 7-Zip linked revalidation (2026-09-12 UTC): the current source configured
and linked the production static `check_clamav` target in the existing AArch64
Linux Docker toolchain. Focused current-source execution passed `7z` 28/28,
`7z_map` 4/4, `7z_cleanup` 1/1, `7z_sfx` 3/3, and `7z_sfx_corpus` 1/1, all with
zero failures and errors. This includes the sticky-completion regression and
the materialized embedded-child corpus path. Source manifest:
`0efece36509e28c0d0268e553acd3b48d8a37035a5896edc14c32e41433901e6`.
This remains development evidence only; certified x86-64, sanitizer,
production-CVD/service, resource, full-size, Sonic1, and final release
qualification remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-7z-linked-revalidation-2026-09-12.md`.

R08 archive-family linked sweep (2026-09-12 UTC): current-source focused
execution passed ARJ (`arj_map` 8/8, `arj_compressed` 2/2, `arj` 14/14,
`arjsfx` 5/5), EGG (`egg_metadata` 1/1, `egg_map` 12/12, `egg_sfx` 3/3),
MSPack/CAB (`mspack_map` 8/8, `mspack` 8/8, `cabsfx` 3/3), AutoIt
(`autoit_map` 9/9, `autoit_corpus` 1/1, `autoit_sfx` 1/1), and NSIS
(`nulsft_map` 2/2, `nulsft` 8/8, `nulsft_corpus` 1/1), all with zero failures
and errors. This strengthens AArch64 development evidence for parser
admission, extraction, cleanup, status, and nested-child paths; no capability
was promoted. Certified x86-64, sanitizer, production-CVD/service, resource,
full-size, Sonic1, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R08-archive-family-linked-sweep-2026-09-12.md`.

R08 ZIP linked sweep (2026-09-12 UTC): current-source focused execution
passed `zip_map` 3/3, `zip_sfx` 5/5, and `zip` 19/19, all with zero failures
and errors. The groups cover central-directory and callback status, weak and
confirmed SFX admission, ZIP64 malformed input, sticky completion, decoder
finalization, and exact nested-child corpus matching. This remains AArch64
development evidence; certified x86-64, sanitizer, production-CVD/service,
resource, full-size, Sonic1, and final release qualification remain open. No
capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-zip-linked-sweep-2026-09-12.md`.

R08 bounded solid EGG stream extraction (2026-09-12 UTC): the production
streaming EGG path now replays a solid archive's shared stream and forwards
only the requested member range for STORE and independently framed BZIP2
blocks, while preserving per-block size and CRC validation. Solid DEFLATE and
LZMA now keep one decoder across block boundaries and are covered by two-block
late-member regressions; solid AZO remains an explicit fail-visible path.
Current-source AArch64 execution passed `egg_map` 16/16, including stored,
BZIP2, persistent-DEFLATE, and persistent-LZMA late-member extraction;
source guards, the regenerated inventory, capability manifest, release
readiness, acceptance map, diff check, and snapshot check passed. Source
manifest: `8f8cb5a60596514421f3724007d0f756fd1c5dddca024328ed015ae858e5db34`.
This remains development evidence only; certified x86-64, sanitizer,
production-CVD/service, resource, full-size, Sonic1, and final release
qualification remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-egg-solid-stream-2026-09-12.md`.

R08 targeted-test fixture dependency (2026-09-12 UTC): `check_clamav` now
depends on the complete decrypted fixture aggregate already used by the
service test. Removing the two generated RAR outputs and rebuilding only the
target regenerated both files and restored the expected 53/53 fixture count.
The complete current-source ARM64 CTest matrix then passed 15/15 in 156.15
seconds, including all 2,915 `libclamav` checks. Source guards, snapshot
freshness, and diff checks passed; no capability was promoted. This remains
development evidence only, with certified x86-64, sanitizer, full-size,
production-CVD/service, Sonic1, and final release gates open. Receipt:
`docs/largefile-task-receipts/R08-egg-solid-stream-2026-09-12.md`.

R03 current-source Release matrix (2026-09-12 UTC): the current source built
successfully in Release mode with shared and static libraries, application,
UnRAR, milter, on-access, and tests enabled. The private-entry-point harness
used the static library while application binaries used the shared build. The
source manifest is `257282d76e128071449421a7eab0fdfe1ea2901e8b4f7c3da2e9e2483b96ae43`
and the Release CMake cache is
`ccb75198e830592855c11379070858f637ec45bdbcb97d923c4ca4ce9cf80ab3`. The
identity-bound CTest matrix passed 16/16 in 156.91 seconds, including
libclamav, Rust, clamscan, clamd, freshclam, sigtool, milter, ingress, and all
large-file control/evidence tests. This is AArch64 Docker development evidence
only; no capability was promoted and certified x86-64, sanitizer, full-size,
production-CVD/service, Sonic1, and final release gates remain open. Receipt:
`docs/largefile-task-receipts/R03-current-source-release-2026-09-12.md`.

R08 MBR zero-start partition admission (2026-09-12 UTC): MBR and EBR now
reject typed partition entries beginning at LBA zero before nested dispatch;
the direct regression is fail-visible through `CL_EFORMAT`, incomplete-scan,
and non-cacheable context state. Current-source ARM64 Release execution
passed `mbr` 12/12, `mbr_corpus` 1/1, and `partition_map` 5/5. Source guards,
inventory, snapshot, and diff checks passed after refresh. Source manifest:
`26b5c4569dc7ae5cf6f3465f93bfd42e0a2a3e074898cd94ebb408550669bfee`. The
complete current-source ARM64 Release CTest matrix then passed 16/16 in
122.00 seconds after rebuilding all affected targets. This remains
development evidence only; no capability was promoted and certified
x86-64, sanitizer, full-size, production-CVD/service, Sonic1, resource, and
final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R08-mbr-zero-start-admission-2026-09-12.md`.

R10 clamd `ReadTimeout=0` stream semantics (2026-09-12 UTC): the daemon now
preserves the zero timeout sentinel through `INSTREAM` parsing and handling,
so a client may pause after a partial chunk and still complete a valid stream.
The focused current-source ARM64 Release clamd test passed 1/1 in 32.50
seconds, including 17 Python cases covering both legacy and structured
zero-timeout pause/resume paths. Host-side source guards, snapshot freshness,
and diff checks passed. The remaining current-source ARM64 Release CTest
targets, excluding the separately run `clamd` and source-guard tests, then
passed 14/14 in 130.10 seconds; together these targeted runs cover all 16
registered CTest targets without claiming one combined resource-limited
invocation. A later full ARM64 CTest attempt passed `libclamav` and
`largefile_poc_fail_closed` but was resource-killed with exit 137 while
starting `largefile_source_guards`; it is not counted as a complete matrix
pass. Source manifest:
`064540666ce4a83742c68e5e0aedcf5f1673e41b6019f305841de64470ebf499`. This
remains development evidence only; no capability was promoted and certified
x86-64, sanitizer, full-size, production-CVD/service, Sonic1, resource, and
final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R10-clamd-read-timeout-zero-2026-09-12.md`.

R10 daemon receive deadline edge (2026-09-12 UTC): the per-descriptor receive
loop now expires a positive `ReadTimeout` at `now >= timeout_at` instead of
granting an extra polling interval at the exact deadline, while preserving the
zero sentinel for indefinite reads. Current-source ARM64 Release `clamd` and
`clamdscan` rebuilt successfully, and the registered `clamd` target passed
1/1 in 32.91 seconds with the 17-case stream-timeout suite. The source guard,
snapshot, and diff checks passed. The positive-deadline regression is included
in the 18-case daemon suite. The resulting source manifest is
`04aa4a408357b560a7a6d139cc5ba382bfa1a8d74a3c19ff12005b9a4381c730`; no
capability was promoted. Certified x86-64, sanitizer, full-
size, service, resource, Sonic1, R04, and final release qualification remain
open. Receipt: `docs/largefile-task-receipts/R10-read-deadline-edge-2026-09-12.md`.

R10 structured service capture (2026-09-12 UTC): the current-source ARM64
Release binaries completed 24 R04-shaped service records: six direct clamd
structured report modes and clamdscan `fdpass`/`stream`, each with clean,
detection, and limit outcomes. The result distribution was eight
`COMPLETE`, eight `DETECTION_TERMINATED`, and eight `LIMIT_INCOMPLETE`; all
three daemon lifecycle records proved PING health before and after cases and
clean socket/PID-file removal. The independent acceptance-record verifier
passed all 24 records. The first attempt failed closed because the test CA
directory was not supplied; rerunning with the repository's `/src/certs`
directory resolved that configuration prerequisite. This is development-only
ARM64 evidence and does not promote capabilities; certified x86-64, sanitizer,
full-size, production-CVD, resource, Sonic1, and final release qualification
remain open. Receipt:
`docs/largefile-task-receipts/R10-structured-service-capture-2026-09-12.md`.

R04/R10 development service capture certificate default (2026-09-12 UTC):
`tools/largefile_development_service_capture.py` now defaults to the
repository test CA and rejects missing or symlinked certificate directories,
matching the existing clamscan development capture. Its focused test passed
8/8. After rebuilding current-source ARM64 Release `clamd` and `clamdscan`, a
fresh capture without an explicit certificate argument wrote 24 R04 records;
the independent verifier passed all 24. This is development-only evidence and
does not promote capabilities; certified x86-64, sanitizer, full-size,
production-CVD, resource, Sonic1, and final release qualification remain open.
Receipt: `docs/largefile-task-receipts/R04-development-service-certs-default-2026-09-12.md`.

R04 clamscan development acceptance capture (2026-09-12 UTC): the current-
source ARM64 Release `clamscan` produced six fresh R04 records for file and
stdin clean, detection, and max-file-size limit edges. The repository CA was
resolved by default, exact detection offset `25` and the exact
`Heuristics.Limits.Exceeded.MaxFileSize` reason were bound into the records,
and the independent acceptance verifier passed all 6. Retained evidence is
`/tmp/clamav-dev-acceptance-20260912f`; this is development-only evidence and
does not promote capabilities or satisfy certified, full-size, production-CVD,
resource, Sonic1, or final release qualification. Receipt:
`docs/largefile-task-receipts/R04-development-acceptance-capture-2026-09-12.md`.

R10 development clamdscan client-mode matrix (2026-09-12 UTC): the capability
manifest and case map now explicitly represent default, fdpass, stream,
multiscan, stream-multiscan, and fdpass-multiscan client ingress. The corrected
development capture bound the option tuples to their string capability IDs and
produced 36 fresh R04 records: six direct structured clamd modes and six
clamdscan modes, each with clean, exact detection, and MaxFileSize-limit
outcomes. The independent verifier passed all 36; focused mode tests passed
8/8 and the case map now covers 601 capabilities. Retained evidence is
`/tmp/clamav-dev-service-20260912i`. This remains ARM64 development evidence;
certified x86-64, full-size, production-CVD, sanitizer, resource, fanotify,
Sonic1, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R10-development-client-mode-matrix-2026-09-12.md`.

R13 on-access fanotify development run (2026-09-12 UTC): `clamonacc` now uses
`AT_FDCWD` for fanotify pathname marking, path-based continuous/multiscan
commands now enter the structured response path instead of being rejected as
zero-length submissions, and on-access logs distinguish malware detections
from incomplete/error outcomes. The existing ARM64 Release development
container rebuilt `clamonacc`; a privileged disposable run observed real
`FAN_OPEN` events in both default continuous and fd-passing modes, with clamd
returning the exact detection, and exercised the on-access size boundary. The
same event path also reached `INSTREAMREPORT`, `MULTISCANREPORT`, and
`ALLMATCHSCANREPORT` for `--stream`, `--multiscan`, and `--allmatch`; each
returned the exact detection. The source guard protects all three fixes. The
same kernel rejected `FAN_OPEN_PERM` marking with `EINVAL`, so no
prevention/permission evidence was claimed or promoted. Certified x86-64,
full-size, production-CVD, sanitizer, resource, Sonic1, and final release
qualification remain open. Receipt:
`docs/largefile-task-receipts/R13-onaccess-fanotify-development-2026-09-12.md`.

R13 malformed-event follow-up (2026-09-12 UTC): the on-access worker now
handles a queued fanotify event with its fanotify bit set but no copied
metadata object without dereferencing NULL after the scan helper rejects the
context. The current-source ARM64 `clamonacc` target rebuilt successfully;
binary hash is
`39a36a8c582fee4e54c563ca09f08bd7493e7e06459283cfe37a80796d2d12de` and the
source-manifest hash is
`5519e24e83b0ac9354f5d0d7814545cd3bb63d18cd325a2c9173ebd2dba7129c`.
Prior valid-event traces are kept bound to their pre-follow-up binary; no
permission capability was promoted. Source guards and the ARM64 compile are
the current verification, while certified x86-64, full-size, production-CVD,
sanitizer, resource, Sonic1, and real permission-event qualification remain
open. Receipt:
`docs/largefile-task-receipts/R13-onaccess-fanotify-development-2026-09-12.md`.

R13 pathname-boundary follow-up (2026-09-12 UTC): the fanotify event loop now
uses the complete pathname buffer for `/proc/self/fd` resolution and rejects
an actually truncated result before scanning or submitting a path to clamd.
A real privileged ARM64 monitoring run over a 1,238-byte nested pathname
logged the refusal, produced no report for the truncated path, and shut down
the on-access queue cleanly. The rebuilt `clamonacc` hash is
`6478856599524219535c8dfcc3bc464ffcbf8e1746e1d7fd42bc200ed3bb2bd7`, with
source manifest
`66c49bc37c2cd23b1b85ca646cae1d71025ee76e9dc62562a52a5becd3a9fe36`.
Source guards and the target build passed; prior valid-event traces remain
bound to their earlier binary. No permission capability was promoted.
Certified x86-64, full-size, production-CVD, sanitizer, resource, Sonic1,
and real permission-event qualification remain open. Receipt:
`docs/largefile-task-receipts/R13-onaccess-fanotify-development-2026-09-12.md`.

R13 pathname-event recovery follow-up (2026-09-12 UTC): an oversized
resolved fanotify pathname is now rejected as one event and the loop continues
after successful close/deny recovery; only a failed recovery response remains
fatal. The current-source ARM64 monitoring run refused the 1,238-byte fixture,
kept clamonacc live, and then scanned a later unprivileged normal event through
`CONTSCANREPORT`, detecting the exact test signature. Final `clamonacc` hash:
`f724742900bd5cef8103e5f17d65f647c61373e129028c9178cc9597df9bfb21`;
source manifest:
`8d19f02597a5541ce99002b8be7da2a0e60ea97f71fb3d2b8382eba5900cccd4`.
Source guards and the existing current-source build passed; no permission
capability was promoted. Certified x86-64, full-size, production-CVD,
sanitizer, resource, Sonic1, and real permission-event qualification remain
open. Receipt:
`docs/largefile-task-receipts/R13-onaccess-fanotify-development-2026-09-12.md`.

R13 final-source pathname recovery revalidation (2026-09-12 UTC): the
current-source `clamonacc` target was rebuilt and rerun after the source and
inventory refresh. The 1,238-byte fixture was refused, the monitor remained
live, and a later unprivileged normal event reached `CONTSCANREPORT` and
returned the exact test detection. The staged binary hash remained
`f724742900bd5cef8103e5f17d65f647c61373e129028c9178cc9597df9bfb21`; the
current-tree source manifest hash, regenerated after the inventory and
tracked evidence refresh, is
`6831c6997594987bc608aff005204832ff4399f48d79b8ad6dd665a7dcbac7d8`.
The final clamonacc and clamd log hashes are
`8ca59c77d04e4736d6e4fd8e446244dd5c5a3b959136dabe633b3efb8967a160` and
`33adfbfdf0ca38724366d6dbd6c0d070550387d30f96d0cb54c87f60d684fd39`.
Source guards and snapshot freshness checks passed. This remains ARM64
development monitoring evidence; no permission capability was promoted and
certified x86-64, full-size, production-CVD, sanitizer, resource, Sonic1,
and real permission-event qualification remain open. Receipt:
`docs/largefile-task-receipts/R13-onaccess-fanotify-development-2026-09-12.md`.

R13 queue-teardown ownership audit (2026-09-12 UTC): queued on-access events
now retain explicit ownership until dispatch, and queue-owned events remaining
at shutdown release their path/metadata and close or deny any retained
fanotify descriptor through the shared fail-closed helper. Dispatched events
are detached before worker-pool submission so queue teardown cannot free them
while a worker is using them. The current-source ARM64 `clamonacc` target
rebuilt successfully; the current-tree source-manifest hash is
`439eef3f46a381e4dbe6b185d3d7336b5b3cdda867ee5d8d734870e4e98811d9`.
The full source guards and refreshed snapshot passed. This remains an
implementation/cleanup audit without real permission-event evidence; no
capability was promoted. Certified x86-64, full-size, production-CVD,
sanitizer, resource, Sonic1, and final permission qualification remain open.
Receipt:
`docs/largefile-task-receipts/R13-onaccess-fanotify-development-2026-09-12.md`.

R03 current-source CTest matrix (2026-09-12 UTC): the existing ARM64
Release build was checked in three bounded invocations covering all 16
registered CTest targets. `libclamav`, `libclamav_rust`, `clamd`, clamscan,
freshclam, sigtool, milter, and all large-file release-control tests passed;
each invocation exited 0. The build identity was bound to current-tree source
manifest `439eef3f46a381e4dbe6b185d3d7336b5b3cdda867ee5d8d734870e4e98811d9`.
This is current-source ARM64 development verification only: no capability was
promoted, and certified x86-64, sanitizer parity, full-size materialized
workloads, production databases, resource/fanotify qualification, and final
release evidence remain open. Receipt:
`docs/largefile-task-receipts/R03-current-source-ctest-2026-09-12.md`.

R13 inotify record-boundary and local-help audit (2026-09-12 UTC): the
dynamic-directory event loop now bounds every inotify header/name length to
the current read and requires an in-record NUL before any path string use;
validated records always advance, including unknown watch descriptors and
nameless events. A malformed tail is discarded visibly without unchecked
pointer advancement. `clamonacc --help` now exits 0 with usage output before
daemon configuration parsing or privileged fanotify startup. The current
source rebuilt `clamonacc` warning-clean, source guards passed, and the
focused large-file CTest control slice passed 3/3. Source manifest:
`7f6c7387913854f6527445a602e10521f46c36d2e594a592921e2156fd054ac4`;
`clamonacc` hash:
`0d24a6ed8b91796d7cc504c1844f06763c5e55d82da4f8ce06e66ff597e32a6e`.
This remains ARM64 development evidence without kernel-injected malformed
inotify or real fanotify permission-event qualification. Receipt:
`docs/largefile-task-receipts/R13-onaccess-fanotify-development-2026-09-12.md`.

R13 inotify hierarchy-state audit (2026-09-12 UTC): the recursive watch
bookkeeping now rejects zero/oversized watch limits before doubled allocation,
empty hierarchy paths before final-byte indexing, and stale watch descriptors
before lookup-table clearing. The current-source ARM64 `clamonacc` target
rebuilt warning-clean; source guards and the focused large-file CTest slice
passed (`3/3`). Inventory: 44,670 lines, SHA-256
`6b965f6fd0c565940b580a44f7d5564b8bbe3a3e4de17b2a4b629ad9a68e0813`.
Source manifest:
`825ae463132f8c095a87fd77702e09f4f6b3a815e1b04dc308da033a8b194f1b`;
`clamonacc` hash:
`b2d0ef4ba1725d5dcdc21dbd772b32b13d201f475ffea2b6be98726eb29393bd`.
This remains ARM64 development evidence without real fanotify permission
qualification; no capability was promoted. Receipt:
`docs/largefile-task-receipts/R13-onaccess-fanotify-development-2026-09-12.md`.

R03 current-source CTest revalidation (2026-09-12 UTC): after the R13
inotify hierarchy-state changes, all 16 registered current-source ARM64
Release CTest targets were rerun in three bounded serial invocations and
passed: `3/3` (`libclamav`, `libclamav_rust`, `clamd`), `10/10` release-control
and milter targets, and `3/3` (`clamscan`, `freshclam`, `sigtool`). The source
manifest is
`825ae463132f8c095a87fd77702e09f4f6b3a815e1b04dc308da033a8b194f1b`; current
`clamonacc` is
`b2d0ef4ba1725d5dcdc21dbd772b32b13d201f475ffea2b6be98726eb29393bd`.
This is development verification only; certified x86-64, sanitizer, full-size
materialized, production-CVD, resource, and real fanotify permission evidence
remain open. Receipt:
`docs/largefile-task-receipts/R03-current-source-ctest-2026-09-12.md`.

R13 process-tree service resource measurement (2026-09-12 UTC): service
qualification now follows every active clamd, clamdscan, queue-client, and
milter root through Linux procfs `PPid` records and sums each descendant's
`VmRSS` once. The service evidence verifier requires the explicit
`procfs-process-tree-vmrss` marker, sampler identity, and a nonzero process
count at the measured peak; daemon-only evidence is rejected. A real
parent/child sampler regression, the service-evidence verifier, source guards,
runtime-evidence controls, and acceptance schema all passed in the current
ARM64 container (focused CTest `5/5`, exit 0). The complete 18-test current
source CTest set then passed in bounded slices (`3/3`, `12/12`, and `3/3`),
each with exit 0. Current source-manifest SHA-256 is
`7ed2dc136662b3a8b86ed0727f720d007dfd47cef6862fe4109b078c941594c9`.
This remains instrumentation/verifier development evidence: no full-size
service run or certified x86-64 resource qualification was claimed, and PCRE
phase, PSS/swap, production-CVD, Sonic1, fanotify permission, sanitizer-parity,
and release evidence remain open. Receipt:
`docs/largefile-task-receipts/R13-process-tree-resource-sampler-2026-09-12.md`.

R13 PCRE runtime phase markers (2026-09-12 UTC): the full-map matcher now
emits debug-only `before-pcre`, `pcre`, and
`post-pcre-before-deep-parse` events after the subject is mapped and released;
the parser dispatch boundary emits `deep-parse`. The independent PCRE proof
verifier now reads the retained process log and rejects missing, out-of-order,
or release-unbound markers. The existing Linux ARM64 Release build rebuilt
`clamscan`, the PCRE evidence regression passed 10/10, and the focused current
source CTest slice passed 5/5. Source manifest:
`ae5a9f964fcc2ec91e3f613ca63030e0aeb3d0d3c43cd3bd8dfb64fa7b4a32f1`;
tracked inventory: 44,674 lines, SHA-256
`c38bf34d1f45d55640bed835724b322e162c914d745160f9e3d0833f3dc3aab4`.
A disposable PCRE scan emitted the matcher markers and exact custom alert,
but its test-CVD parser ordering was intentionally not accepted as a
qualification sequence. This remains instrumentation/verifier development
evidence; full-size PCRE, certified x86-64, RSS/PSS/swap, production-CVD,
sanitizer, Sonic1, fanotify permission, and release qualification remain
open. Receipt:
`docs/largefile-task-receipts/R13-pcre-runtime-markers-2026-09-12.md`.

R13 process-tree memory and I/O metrics (2026-09-12 UTC): the service
qualification runner now retains aggregate Linux procfs samples for VmRSS,
PSS (`smaps_rollup`), VAS, VmSwap, minor/major faults, and read/write I/O for
all active service roots and descendants. The producer and independent
verifier require the exact expanded schema, reject missing selected-process
metrics, enforce PSS/VAS relationships and zero observed swap, and compare all
counter peaks with the summary. The real Linux sampler regression, service
evidence regression, source guards, and focused CTest passed; focused CTest
was `3/3` in the existing ARM64 development container. Retained log:
`/private/tmp/clamav-r13-metrics-focused-20260912.log`, SHA-256
`f73414d70e3c04da6d3561416c8cfb7810147b076d1743e45346aadf9f4f36a4`.
Current source manifest SHA-256:
`f8130229ca77715c899163e61172416aaec77ad1b0f90c32347d0e5047cffa8a`;
tracked inventory remains 44,674 lines, SHA-256
`c38bf34d1f45d55640bed835724b322e162c914d745160f9e3d0833f3dc3aab4`.
This is development instrumentation evidence only: it does not establish
historical OOM-event proof, per-parser R14 canary records, PCRE phase
qualification, full-size production-CVD service behavior, sanitizer parity,
real fanotify permission responses, or release readiness. Receipt:
`docs/largefile-task-receipts/R13-process-tree-metrics-2026-09-12.md`.

R13 cgroup-v2 OOM observability (2026-09-12 UTC): service qualification now
captures a pre-run cgroup identity and `memory.events` baseline, retains
`oom`/`oom_kill` counters with each process-tree resource sample, rejects
cgroup identity changes or counter increases, and checks the final counters
after service cleanup. The real Linux cgroup-v2 sampler regression, service
evidence regression, source guards, process-tree metrics regression, and
focused CTest passed (`4/4`) in the existing ARM64 development container.
Retained log: `/private/tmp/clamav-r13-oom-focused-20260912.log`, SHA-256
`0834965d39db0774f5c1893272b4fd83c4b0b14ee4e5d10745b3863c37a1b4ba`; the
final post-identity-binding focused log is
`/private/tmp/clamav-r13-final-focused-20260912.log`, SHA-256
`f75cf7b5d94ad45158adc7a88949db2d0a1319146b408d6b72dffa20538e39f1`.
Current source-manifest SHA-256:
`e10f52fa7a6fa26bf32f4a1fb61061a0c0173027b78e4200d5e61679d5bf3eb3`;
tracked inventory remains 44,674 lines, SHA-256
`c38bf34d1f45d55640bed835724b322e162c914d745160f9e3d0833f3dc3aab4`.
This remains development evidence only; full-size certified x86-64,
per-parser canary, PCRE phase, sanitizer-parity, production-CVD, Sonic1,
fanotify permission, and release-readiness requirements remain open. Receipt:
`docs/largefile-task-receipts/R13-cgroup-oom-observability-2026-09-12.md`.

R14 per-case resource contract (2026-09-12 UTC): acceptance records now have
an independent `provenance/acceptance-case-resources.tsv` sidecar contract for
per-case process-tree RSS/PSS/VAS, swap, page faults, I/O, temporary peaks,
OOM counters/cgroup identity, and PCRE phase peaks. The sidecar binds
source/build/config/platform identities, requires certified Linux x86-64
procfs sampling, rejects nonzero swap and invalid memory relationships, and
requires every requested capability case. `--bind` adds the sidecar hash and
retained artifact path to every case record; authoritative release readiness
now requires this binding, while development captures remain allowed to omit
it. The new producer samples a live command tree through the existing procfs
and cgroup-v2 samplers, tracks recursive temporary usage, supports ordered PCRE
phase markers, validates before writing, and preserves command exit results.
The full host tool suite passed 156 tests with 2 expected Linux-only skips.
Reused current-source ARM64 CTest passed `4/4`: source guards, acceptance
schema, resource schema, and resource-capture producer. A real ARM64 Linux
capture sampled a live process but correctly failed the certified x86-64 gate;
a fresh retry confirmed no invalid sidecar row was emitted. Current source
manifest: 1,693 lines, SHA-256
`a1fd05c7b23dfe0b12e2ca8278dcc759508a4a9d27a0791e1cdb2ad9769ba946`.
Certified x86-64, full-size, production-CVD, sanitizer, Sonic1, fanotify
permission, and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R14-per-case-resource-contract-2026-09-12.md`.

R04 acceptance resource producer binding (2026-09-12 UTC): the service
acceptance producer now accepts an independently captured resource sidecar and
binds it through the strict R14 verifier when requested. `--require-resource-
sidecar` requires the default sidecar, while existing development captures
remain unchanged without the option. The producer integration regression
passes 9/9, including exact sidecar hash/path binding; the reconfigured
current-source focused CTest passed 6/6, including both direct producer
targets. The service qualification runner now captures separate live
daemon-plus-client process-tree peaks for each mapped workload, finalizes the
sidecar after the complete build identity is written, and requires that
sidecar during authoritative record production. The full source-guard sweep
passed after this integration. Current source manifest: 1,693 lines, SHA-256
`f2db32e87842c846da4d8064bc546930f7d7d9787a2ec676db12e07b6e9d0faf`. No
capability was promoted; certified x86-64, format-8 compiler/artifact, full-size,
production-CVD, sanitizer, Sonic1, fanotify permission, and final release
evidence remain open. Receipt:
`docs/largefile-task-receipts/R04-acceptance-resource-producer-binding-2026-09-12.md`.

R03 current-source rebuild and full CTest revalidation (2026-09-12 UTC): after
the service per-case resource integration, the current mounted source was
reconfigured and rebuilt successfully in the existing ARM64
`rust:1.97-bookworm` container. The complete configured CTest invocation passed
`24/24` in `203.56` seconds, covering the library, Rust, CLI, daemon,
freshclam, sigtool, milter, acceptance/evidence, procfs, OOM, and service
evidence suites. The container was stopped after verification. Current source
manifest SHA-256:
`f2db32e87842c846da4d8064bc546930f7d7d9787a2ec676db12e07b6e9d0faf`. This is
development verification only; certified x86-64, full-size, sanitizer,
production-CVD, Sonic1, PCRE/queue, fanotify permission, and final release
evidence remain open. Receipt:
`docs/largefile-task-receipts/R03-current-source-ctest-2026-09-12.md`.

R11 development service vertical slice (2026-09-12 UTC): the current-source
Release `clamd` and `clamdscan` binaries exercised all six structured clamd
report commands and six client modes over clean, detection, and small-limit
fixtures. The live run produced 36 bound R04 records: 12 `COMPLETE`, 12
`DETECTION_TERMINATED`, and 12 `LIMIT_INCOMPLETE`; the independent case-map
validator accepted all 36, and each outcome group proved daemon health and
cleanup. This remains Linux-aarch64 development evidence only; certified
x86-64, exact 32-GiB, resource-sidecar, production-CVD/Sonic1, sanitizer,
fanotify permission, and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R11-development-service-vertical-slice-2026-09-12.md`.

R13 on-access thread-pool admission (2026-09-12 UTC): `clamonacc` now rejects
zero, negative, and out-of-range `OnAccessMaxThreads` values before startup,
and the bundled thread-pool constructor refuses zero-worker pools and native
allocation-size overflow. This prevents an accepted fanotify event from
entering a queue with no worker able to deliver its response. A direct
one-worker execution regression and an application-level invalid-config test
passed; the reconfigured current-source ARM64 Release CTest matrix passed
`26/26`, and the final source guards, snapshot freshness check, and diff check
passed. This is development verification only; certified x86-64, exact
32-GiB, sanitizer, resource-sidecar, production-CVD/Sonic1, and real fanotify
permission evidence remain open. Receipt:
`docs/largefile-task-receipts/R13-onaccess-threadpool-admission-2026-09-12.md`.

R13 on-access thread-pool lifecycle (2026-09-12 UTC): the bundled pool now
fails visibly when `pthread_create()` rejects a worker, waits on a condition
variable rather than spinning forever for startup, and joins every created
worker before releasing queue or pool memory. A Linux linker-wrapped `EAGAIN`
regression proved failed startup returns promptly; the normal one-worker
execution and invalid `OnAccessMaxThreads` admission cases remained green.
The current-source ARM64 Release build was reconfigured and the full CTest
matrix passed `26/26` in `168.09` seconds; source guards, snapshot freshness,
and diff checks also passed. Current source-manifest SHA-256:
`38e4a79612532a9360240686f59ba86c3d2ada046a82db8843bca6ec5bc57a77`.
This remains development verification only; certified x86-64, exact 32-GiB,
sanitizer, resource-sidecar, production-CVD/Sonic1, and privileged fanotify
permission evidence remain open. Receipt:
`docs/largefile-task-receipts/R13-onaccess-threadpool-lifecycle-2026-09-12.md`.

R10 clamd thread-pool admission (2026-09-12 UTC): clamd now starts a needed
worker before publishing a dispatch item, rejects `pthread_create()` failure,
and restores consumed capacity when reserved admission cannot be completed.
This closes the prior path where a successful dispatch could leave a request
permanently queued with no worker. The Linux linker-wrapped `EAGAIN`
regression covered ordinary dispatch failure, reserved-dispatch retry after
reservation restoration, and normal callback execution. The regenerated
current-source ARM64 Release build passed the complete CTest matrix `27/27` in
`175.01` seconds; source guards, snapshot freshness, and diff checks also
passed. Current source-manifest SHA-256:
`9d9c01e047b48b64d127ea9eea68feb96d769a70da1783998bb07494eada79dc`.
This remains development verification only; certified x86-64, exact 32-GiB,
sanitizer, resource-sidecar, production-CVD/Sonic1, and privileged fanotify
permission evidence remain open. Receipt:
`docs/largefile-task-receipts/R10-clamd-threadpool-admission-2026-09-12.md`.

R10 milter connection-pool startup (2026-09-12 UTC): `cpool_init()` now
returns an explicit status, rejects monitor-thread creation failure, cleans up
the partial socket pool, and prevents `clamav-milter` from continuing with an
unusable non-null pool. A Linux linker-wrapped `EAGAIN` regression covered
failed startup, successful monitor startup, and cleanup; the existing milter
quota and protocol tests remained green. The regenerated current-source ARM64
Release build passed the complete CTest matrix `28/28` in `272.76` seconds;
source guards, snapshot freshness, and diff checks also passed. Current source
manifest SHA-256:
`38c4763f8df4a5ba68f9523cfa5ddd72cf3933c42dc6ac47da61a0be7654765c`.
This remains development verification only; certified x86-64, exact 32-GiB,
sanitizer, resource-sidecar, production-CVD/Sonic1, and privileged fanotify
permission evidence remain open. Receipt:
`docs/largefile-task-receipts/R10-milter-connpool-startup-2026-09-12.md`.

R10 clamd numeric limits and queue arithmetic (2026-09-12 UTC): generic
numeric configuration options now use checked `strtoll()` conversion, and
clamd validates `MaxThreads` and `MaxQueue` before narrowing them to thread-pool
types. Queue-limit derivation now detects recursion/thread multiplication and
descriptor-budget overflow, avoids low-limit unsigned underflow, and caps the
effective queue at `INT_MAX`. Parser and arithmetic edge-case unit tests were
added. The regenerated current-source ARM64 Release build passed the complete
CTest matrix `28/28` in `215.36` seconds; source guards, snapshot freshness,
and diff checks also passed. Current source-manifest SHA-256:
`4a5c5e7544f752830511a833b4467106708e2b7c848b4862c4c18e6695107546`.
This remains development verification only; certified x86-64, exact 32-GiB,
sanitizer, resource-sidecar, production-CVD/Sonic1, and privileged fanotify
permission evidence remain open. Receipt:
`docs/largefile-task-receipts/R10-clamd-limit-arithmetic-2026-09-12.md`.

R08 HFS+ ExtentOverflow resolution (2026-09-12 UTC): HFS+ fork extraction now
resolves checked ExtentOverflow B-tree records after the eight inline extent
descriptors are exhausted. Records are bound to fork type, catalog file ID,
and logical starting block; node offsets, key/descriptor geometry, volume
coordinates, leaf-chain termination/counts, cycles, missing records, recursive
ExtentOverflow overflow, and scan deadlines remain fail-visible and
non-cacheable. A production-linked synthetic regression follows both a
catalog leaf chain and a nine-block data fork through overflow-only blocks and
reaches the exact child signature. Focused `hfs_fork` passes `2/2`, and the
current-source ARM64 Release CTest matrix passes `28/28` in `165.40` seconds;
source guards, inventory freshness, status snapshot freshness, and
`git diff --check` also pass. Current source-manifest SHA-256 is recorded in
the receipt as
`436caac47eb38f1de6470bba94e1ca61ba30b80cf3f7cf018eb897caf46300ce`. This remains development
verification only; complete HFS+ corpus, sanitizer/leak, certified Linux
x86-64, production-CVD/service, materialized-large-file/resource, Sonic1,
and final parser/release qualification remain open. Receipt:
`docs/largefile-task-receipts/R08-hfsplus-extent-overflow-2026-09-12.md`.

R08 HFS+ ExtentOverflow chain-tail hardening (2026-09-12 UTC): a matching
overflow record is now retained while the complete declared leaf chain is
validated, so a self-linked or otherwise malformed tail cannot be bypassed.
The production-linked `hfs_fork` case remains `2/2`, and the linked `libclamav`
CTest target reports `2,918` checks with zero failures and errors. Source
guards, snapshot freshness, and `git diff --check` pass. The current source
manifest is 1,697 entries with SHA-256
`52802577d6c2fe851d98801dc257a6c11f85ea70f961b35c6d1844fb3486878c`. This is
development verification only; complete HFS+ corpus, sanitizer/leak, certified
Linux x86-64, production-CVD/service, materialized-large-file/resource,
Sonic1, and final parser/release qualification remain open. Receipt:
`docs/largefile-task-receipts/R08-hfsplus-extent-chain-tail-2026-09-12.md`.

R08 HFS+ resource-fork ExtentOverflow coverage (2026-09-12 UTC): the
production-shaped HFS+ fixture now resolves separate data- and resource-fork
records after their eight inline extents, while retaining the self-linked-tail
fail-closed regression. Focused `hfs_fork` passes `2/2`, and the linked
`libclamav` CTest target reports `2,918` checks with zero failures and errors.
The current 1,697-entry source manifest is
`e22940b895d3f25943495ce72737e9a41a592891e28861861918ead460d32b0`. This is
development verification only; complete HFS+ corpus, sanitizer/leak,
certified Linux x86-64, production-CVD/service, materialized-large-file/
resource, Sonic1, and final parser/release qualification remain open. Receipt:
`docs/largefile-task-receipts/R08-hfsplus-resource-fork-overflow-2026-09-12.md`.

R08 HFS+ derived-inventory reconciliation (2026-09-12 UTC): the first
post-resource-fork full CTest run passed 27/28 targets; the only failure was
the source guard rejecting the stale tracked inventory. The generated
`docs/largefile-inventory.tsv` was refreshed to 44,877 lines and matched a
second independent generator run byte-for-byte. The repaired source guard
passed as CTest `1/1`, and a complete rerun then passed `28/28` configured
CTest targets in `332.49` seconds. The 601-entry capability validator,
snapshot freshness, and `git diff --check` also passed. The current
1,697-entry source manifest is
`6fb259e48bb36879ff8464826a0922779259bceaa98fd4787af9974b19af3b6b`; the
inventory SHA-256 is
`4f6c40a1ce3148c023d7968e0170c20c91d6c082bde661a358c227476537f22`. This is
development bookkeeping evidence only and does not promote HFS+ or change the
release boundary. Receipt:
`docs/largefile-task-receipts/R08-hfsplus-inventory-refresh-2026-09-12.md`.

R08 no-mempool bytecode allocation ownership (2026-09-12 UTC): the
`DISABLE_MPOOL` bytecode API now applies bounded zero-size and
`CLI_MAX_ALLOCATION` admission, tracks successful `cli_max_malloc()` buffers
in the context, and frees them during context reset; a focused regression
covers rejected sizes and ownership. The ARM64 Release static variant built
all applications and test targets, passed the focused bytecode suite `25/25`,
and passed the complete configured CTest matrix `28/28` in `229.29` seconds,
including the full `libclamav` suite at `2,919` checks. The refreshed 44,885-line
inventory and source guards passed. The post-change 1,697-entry source
manifest SHA-256 is
`3d146e1b5ab18ac7e158cac6e96b88c39952a1eca8ff4ceb1d4e0bd405a7b13e`. This
remains development verification only; certified Linux x86-64, exact 32-GiB,
sanitizer, production-CVD/service, Sonic1, and final allocator-variant
qualification remain open. Receipt:
`docs/largefile-task-receipts/R08-bytecode-no-mpool-2026-09-12.md`.

R06 modern OneNote CTest timeout correction (2026-09-12 UTC): the current
Release-linked `rust_onenote` suite passed `4/4`, including the logical
256 MiB-plus-one corpus attachment streaming case. A fresh full CTest run
identified that the deterministic service-evidence verifier exceeded the
generic 60-second CTest allowance without an internal failure; its allowance
was raised to the documented 300 seconds. The focused verifier then passed
`1/1` in 219.53 seconds, and the complete Release matrix passed `28/28` in
282.83 seconds. Current source-manifest SHA-256 is
`0eb96c128b88b2f3bfa379dbdacbac84923e9dde49d6acd8912f8bc0af4bc721` across
1,697 entries. This remains development verification only; certified Linux
x86-64, exact 32-GiB, sanitizer, production-CVD/service, Sonic1, privileged
fanotify, materialized-edge, and final release qualification remain open.
Receipt: `docs/largefile-task-receipts/R06-modern-onenote-citest-timeout-2026-09-12.md`.

R03/R08 focused sanitizer follow-up (2026-09-12 UTC): the disposable ARM64
`rust:1.97-bookworm` container built the current source with C ASan/UBSan.
With the repository's existing CVD test certificates supplied, the
production-linked `rust_onenote` suite passed `4/4`, HFS+ `hfs_fork`
passed `2/2`, and the full bytecode suite passed `88/88`, all with leak
detection enabled and no sanitizer diagnostics. The HFS+ fixture's first
mapped scan is now closed before replacement, removing the reported 312-byte
fixture leak. The source guards, 601-entry capability manifest, snapshot and
acceptance validators, and `git diff --check` passed after derived-inventory
regeneration. Current source-manifest SHA-256:
`206d81a16538b85a5fe0fc9ac5c622b4163eb185e942b87854fda5fc3a98ca89`
(1,697 entries). This remains focused ARM64 development evidence; certified
Linux x86-64, nightly Rust sanitizer, exact 32-GiB/materialized resource,
production-CVD/service, Sonic1, privileged fanotify, and final release
qualification remain open. Receipt:
`docs/largefile-task-receipts/R08-hfsplus-extent-overflow-2026-09-12.md`.

R03 Rust sanitizer runner target selection (2026-09-13 UTC): removed the
duplicate x86-64-only Cargo runner environment from `unit_tests/CMakeLists.txt`
so `cmake/FindRust.cmake` is the single target-aware implementation. Also
gated the `largefile_clamscan_admission` CTest registration on `ENABLE_APP`,
allowing library-only test configurations to generate without a missing
`clamscan` target. The full application ARM64 CMake configure completed with
static tests and C ASan/UBSan flags. Generated CTest evidence uses
`CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER` and Cargo target
`aarch64-unknown-linux-gnu`; the focused `libclamav_rust` CTest passed `1/1`
in `59.74` seconds. Source guards and `git diff --check` passed. An alternate
toolchain image lacked an OpenSSL development header, but the preserved full
sanitizer container supplied the existing headers and completed the test; no
package installation occurred. Current 1,697-entry source manifest SHA-256 is
`83c55df9a3eb4ca55ac7b6fa0f24f24d6aa88adc50320c69fd60a2c187c7746d`. This is
ARM64 development/configuration evidence only; certified x86-64, exact
32-GiB/materialized resources, production service/CVD, privileged fanotify,
Sonic1, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R03-rust-sanitizer-runner-2026-09-12.md`.

R13 on-access configuration cleanup (2026-09-13 UTC): the rebuilt ARM64
sanitizer test caught a 91-byte `onas_init_context` leak when invalid
`OnAccessMaxThreads` configuration returned before the normal cleanup label.
`clamonacc` now routes option parsing, logger, daemon-config, worker-count,
and daemonize failures through its existing context cleanup, preserving the
fail-closed exit codes. The rebuilt focused admission test passed `1/1` with
LeakSanitizer, and the four on-access/clamd/milter pool tests passed `4/4` in
`5.15` seconds. The surrounding application/release-control subset was
`26/27` before the fix, with the leak as its only failure. Current 1,697-entry
source manifest SHA-256:
`5a2baef1ece4b0d64579fb8380b03f62b751e79dd584342c318c9fcd9aeec593`. This is
ARM64 development sanitizer evidence only; certified x86-64, exact
32-GiB/materialized resources, privileged fanotify, production service/CVD,
Sonic1, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R13-onaccess-config-cleanup-2026-09-13.md`.

R03 current application sanitizer revalidation (2026-09-13 UTC): rebuilt the
full current-source application and test tree at single-job concurrency to
100%, including `clamscan`, `clamd`, `clamonacc`, `clamav-milter`, `sigtool`,
and the added pool binaries. The four pool/configuration tests pass `4/4`
under C ASan/UBSan with LeakSanitizer; the rebuilt application, milter,
release-control, and previously failing on-access configuration evidence
combine to cover the non-aggregate 27-test subset `27/27`. The bounded
`CK_RUN_SUITE=cl_suite CK_RUN_CASE=cl_api` CTest invocation passes all `520`
checks in `610.67` seconds without sanitizer diagnostics. The unfiltered
`libclamav` wrapper remains an honest `1,200`-second timeout on this ARM64
development host, so remaining Check TCase groups must stay bounded rather
than being relabeled as a pass. Current 1,697-entry source manifest SHA-256:
`5a2baef1ece4b0d64579fb8380b03f62b751e79dd584342c318c9fcd9aeec593`. This is
development evidence only; certified x86-64, exact 32-GiB/materialized
resources, production service/CVD, privileged fanotify, Sonic1, and final
release qualification remain open. Receipt:
`docs/largefile-task-receipts/R03-rust-sanitizer-runner-2026-09-12.md`.

R03 bounded parser-family sanitizer follow-up (2026-09-13 UTC): current-source
ARM64 sanitizer CTest TCase invocations passed `1/1` for `rust_onenote`,
`hfs_fork`, `rust_alz`, `rust_lha`, `7z`, `zip`, `pdf`, `required_unsupported`,
`parser_regressions`, `rust_map`, `7z_sfx`, `hfs_map`, and `mspack`, with no
ASan/UBSan diagnostics. The complete `cl_api` TCase passed all `520` checks in
`610.67` seconds. A one-hour container lifetime expired between two runs; the
same preserved container was restarted and the remaining cases then passed.
This retains bounded current-source development evidence without treating the
unfiltered suite timeout as a pass. Certified x86-64, exact
32-GiB/materialized resources, production service/CVD, privileged fanotify,
Sonic1, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R03-rust-sanitizer-runner-2026-09-12.md`.

R03 bounded sanitizer corpus follow-up (2026-09-13 UTC): 25 additional
current-source ARM64 C ASan/UBSan CTest invocations passed `1/1`, covering
PDF, XAR, PE, GIF, Rust LHA, HWP3/HWP OLE2, AutoIt, 7-Zip SFX, TIFF, PNG,
JPEG, CVD, crypt, ELF, TNEF, graphics, callback, hash, and map paths. No
sanitizer diagnostics were emitted. The source-manifest helper was rerun at
1,697 entries with SHA-256
`5a2baef1ece4b0d64579fb8380b03f62b751e79dd584342c318c9fcd9aeec593`.
This is development evidence only and does not replace the unfiltered Check
suite, certified x86-64, exact 32-GiB/materialized, production service/CVD,
privileged fanotify, Sonic1, independent format-8, or final release gates.
Receipt: `docs/largefile-task-receipts/R03-bounded-sanitizer-corpus-followup-2026-09-13.md`.

R03 public scan-API sanitizer follow-up (2026-09-13 UTC): the current-source
ARM64 C ASan/UBSan `cl_scan_api` TCase completed all `836` Check assertions
with zero failures and zero errors. CTest passed `1/1` in `1,039.67` seconds
under the configured timeout, with no sanitizer diagnostics. This remains
development evidence and does not replace certified x86-64, exact
32-GiB/materialized, production service/CVD, privileged fanotify, Sonic1,
independent format-8, or final release qualification. Receipt:
`docs/largefile-task-receipts/R03-bounded-sanitizer-corpus-followup-2026-09-13.md`.

R03 bytecode runtime sanitizer follow-up (2026-09-13 UTC): the correctly
selected `bytecode/arithmetic` TCase completed `52` checks with zero failures
and zero errors, passing `1/1` in `68.74` seconds without ASan/UBSan
diagnostics. A prior `cl_suite/arithmetic` selector produced zero checks and
was discarded. This is development runtime evidence only and does not replace
the independent format-8 artifact required by R07 or any certified/final
qualification gate. Receipt:
`docs/largefile-task-receipts/R03-bounded-sanitizer-corpus-followup-2026-09-13.md`.

R03 additional parser-family sanitizer follow-up (2026-09-13 UTC): ten more
current-source ARM64 C ASan/UBSan CTest invocations passed `1/1` for `mail`,
`mail_partial`, `mhtml`, `tar`, `tar_member`, `iso`, `udf_corpus`,
`apm_corpus`, `gpt_corpus`, and `zip_sfx`; no sanitizer diagnostics were
emitted. This adds MIME, archive, filesystem, partition, and SFX development
coverage only; certified x86-64, exact 32-GiB/materialized, production
service/CVD, privileged fanotify, Sonic1, independent format-8, and final
release qualification remain open. Receipt:
`docs/largefile-task-receipts/R03-bounded-sanitizer-corpus-followup-2026-09-13.md`.

R03 current application smoke (2026-09-13 UTC): the preserved current-source
ASan/UBSan Docker build rebuilt the application and registered test targets to
100% with exit 0, including `clamscan`, `clamd`, `clamdscan`, `clamonacc`,
`clamav-milter`, `sigtool`, and `clambc`. `clamscan` returned `OK` for a clean
fixture and exit 1 with the expected `ClamAV-Test-File.UNOFFICIAL FOUND`
detection for the generated `clam.zip` fixture. This is local ARM64
development smoke evidence only; certified x86-64, exact
32-GiB/materialized, production CVD/service, privileged fanotify, Sonic1,
independent format-8, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R03-application-smoke-2026-09-13.md`.

R10 development service revalidation (2026-09-13 UTC): the current-source
ASan/UBSan build completed the development service capture with exit 0 and 36
validated records: six structured `clamd` commands and six `clamdscan` modes,
each over clean, detection, and limit fixtures. Outcomes were 12
`COMPLETE`, 12 `DETECTION_TERMINATED`, and 12 `LIMIT_INCOMPLETE`; all daemon
instances remained PING-healthy and removed their sockets and PID files during
cleanup. This is ARM64 small-fixture development evidence only; exact
32-GiB/materialized service, production CVD, certified x86-64, milter,
fanotify, Sonic1, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R10-development-service-revalidation-2026-09-13.md`.

R06 focused OneNote reader sanitizer follow-up (2026-09-13 UTC): the existing
ARM64 `RelWithDebInfo` ASan/UBSan tree was reconfigured against the current
source manifest and rebuilt at 100% with exit 0. The focused linked
`cl_suite/rust_onenote` case passed all 4 checks, including the corpus-backed
attachment detection above the former 256 MiB whole-input boundary, with no
ASan/UBSan diagnostics in the captured stderr. The source identity is coherent
at 1,697 manifest entries with SHA-256
`5a2baef1ece4b0d64579fb8380b03f62b751e79dd584342c318c9fcd9aeec593`.
This is ARM64 development evidence only; certified x86-64, exact
32-GiB/materialized resources, production CVD/service, Sonic1, and final
release qualification remain open. Receipt:
`docs/largefile-task-receipts/R06-reader-corpus-attachment-sanitizer-2026-09-13.md`.

R09 fuzzy-image Release integration (2026-09-13 UTC): the fresh
current-source ARM64 Release `clamscan` integration harness passed all 4
`fuzzy_img_hash_test` tests. It exercised exact and distance-bounded
scanner-facing matches, malformed-signature rejection, and both image-scan
disable controls. This is application-level development evidence only;
certified x86-64, production CVD/service, materialized-large-file,
sanitizer/resource, Sonic1, and final release qualification remain open.
Receipt: `docs/largefile-task-receipts/R09-fuzzy-image-release-integration-2026-09-13.md`.

R09 real UnRAR Release integration (2026-09-13 UTC): after correcting the
test fixture's RAR4 header CRC convention, the fresh current-source ARM64
Release `clamscan` test passed 1/1 with the enabled production UnRAR backend.
Both a valid RAR4 archive and a neutral-prefix RAR-SFX produced the expected
nested `RarChild.UNOFFICIAL FOUND` detection without an archive-incomplete
diagnostic. This is development evidence only; complete corpus, sanitizer,
certified x86-64, production CVD/service, materialized-large-file, Sonic1,
resource, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R09-real-unrar-backend-release-2026-09-13.md`.

R10 milter protocol Release integration (2026-09-13 UTC): the registered
current-source ARM64 Release `clamav_milter_protocol` CTest passed 1/1 in
5.38 seconds. Its verbose harness reported clean accept (`a`), malware reject
(`r`), exact configured-limit accept (`a`), and limit-plus-one fail-visible
(`t`) outcomes. The repository CTest profile intentionally uses its 100 MiB
development limit, so literal 32-GiB/certified milter qualification remains
open. Receipt:
`docs/largefile-task-receipts/R10-milter-protocol-release-2026-09-13.md`.

R09 ignored-type Release integration (2026-09-13 UTC): the current-source
ARM64 Release `clamscan` test passed 1/1. A recognized ignored-type input with
the exact raw marker produced `Ignored.Raw.UNOFFICIAL FOUND` while retaining
the unsupported-parser warning; the same-shape nonmatching input returned
exit 2 with `Can't parse data ERROR` and the same explicit warning. This is
development evidence only; sanitizer, certified x86-64, production
CVD/service, materialized-large-file, Sonic1, resource, and final release
qualification remain open. Receipt:
`docs/largefile-task-receipts/R09-ignored-type-release-2026-09-13.md`.

R03 full `clamscan` Release integration (2026-09-13 UTC): the complete
current-source ARM64 Release `clamscan` CTest target passed 1/1 in 16.07
seconds; its underlying integration suite ran 127 tests with zero failures and
zero errors and one expected platform skip. This includes the current parser
corpus, R09 parser-policy and ignored-type cases, fuzzy-image integration, and
the corrected RAR/RAR-SFX backend case. This is development evidence only;
certified x86-64, exact 32-GiB/materialized resources, production CVD/service,
sanitizer/resource, Sonic1, and final release qualification remain open.
Receipt: `docs/largefile-task-receipts/R03-clamscan-full-release-2026-09-13.md`.

R09 required application-row sanitizer follow-up (2026-09-13 UTC): the
current-source ARM64 `RelWithDebInfo` ASan/UBSan `clamscan` passed all 7 tests
in the focused fuzzy-image, Python/ONNX parser-policy, ignored-type, and
production UnRAR/RAR-SFX suites. The run used the current 1,697-entry source
manifest (`ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`)
and emitted no ASan, UBSan, LeakSanitizer, or runtime-error diagnostics. This
is ARM64 development evidence only; certified x86-64, exact
32-GiB/materialized resources, production CVD/service, privileged fanotify,
Sonic1, independent format-8, resource, and final release qualification
remain open. Receipt:
`docs/largefile-task-receipts/R09-required-rows-asan-2026-09-13.md`.

R03 full `clamscan` sanitizer integration (2026-09-13 UTC): the complete
current-source ARM64 `RelWithDebInfo` ASan/UBSan `clamscan` CTest target
passed 1/1 in 183.77 seconds. Its integration harness ran 127 tests with
zero failures and zero errors and one expected platform skip; no ASan, UBSan,
LeakSanitizer, or runtime-error diagnostics were emitted. This broadens
application-facing sanitizer coverage but remains development evidence only;
certified x86-64, exact 32-GiB/materialized resources, production
CVD/service, privileged fanotify, Sonic1, independent format-8, resource,
and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R03-clamscan-full-asan-2026-09-13.md`.

R10 full `clamd` sanitizer integration (2026-09-13 UTC): the complete
current-source ARM64 `RelWithDebInfo` ASan/UBSan `clamd` CTest target passed
1/1 in 233.35 seconds. Its integration harness ran 18 tests with zero
failures and zero errors, covering daemon lifecycle, scan/reload, report and
stream paths, limit outcomes, clamdscan modes, and the `ReadTimeout=0`
structured-stream case. No ASan, UBSan, LeakSanitizer, or runtime-error
diagnostics were emitted. This remains development evidence only; certified
x86-64, exact 32-GiB/materialized resources, production CVD/service,
privileged fanotify, Sonic1, independent format-8, resource, and final
release qualification remain open. Receipt:
`docs/largefile-task-receipts/R10-clamd-full-asan-2026-09-13.md`.

R10 milter application sanitizer integration (2026-09-13 UTC): the current
source ARM64 `RelWithDebInfo` ASan/UBSan quota and protocol targets passed
2/2 in 8.46 seconds. The protocol harness verified clean accept, infected
reject, exact-limit accept, and limit-plus-one fail-visible outcomes, with no
ASan, UBSan, LeakSanitizer, or runtime-error diagnostics. Its 100 MiB
development limit profile is not literal 32-GiB/certified evidence. Receipt:
`docs/largefile-task-receipts/R10-milter-full-asan-2026-09-13.md`.

R03 remaining application executables sanitizer integration (2026-09-13 UTC):
the current-source ARM64 `RelWithDebInfo` ASan/UBSan `freshclam` and `sigtool`
targets passed 2/2 in 41.11 seconds. The `sigtool` harness ran 6 tests with
zero failures and zero errors, and the combined output contained no ASan,
UBSan, LeakSanitizer, or runtime-error diagnostics. This is development
evidence only; certified x86-64, exact 32-GiB/materialized resources,
production CVD/service, privileged fanotify, Sonic1, independent format-8,
resource, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R03-freshclam-sigtool-asan-2026-09-13.md`.

R03/R10/R13 large-file control and Rust sanitizer integration (2026-09-13
UTC): the current-source ARM64 `RelWithDebInfo` ASan/UBSan batch passed 9/9
targets in 11.36 seconds, covering on-access and daemon/milter thread-pool
controls, fail-closed admission, clamscan admission, clamd report protocol,
late ZIP-member detection, and the complete `libclamav_rust` target. Rust ran
159 tests with zero failures; no ASan, UBSan, LeakSanitizer, or runtime-error
diagnostics were emitted. This remains development evidence only; certified
x86-64, exact 32-GiB/materialized resources, production CVD/service,
privileged fanotify, Sonic1, independent format-8, resource, and final
release qualification remain open. Receipt:
`docs/largefile-task-receipts/R03-R10-R13-controls-rust-asan-2026-09-13.md`.

R03 full `libclamav` sanitizer diagnostic (2026-09-13 UTC): the authoritative
current-source ARM64 ASan/UBSan CTest target failed closed at its configured
1,200-second aggregate timeout with exit 111 from `check_clamav`; no
assertion or sanitizer diagnostic was emitted. A follow-up direct
`cl_suite` run with per-case `T=1800` was stopped after approximately 30
minutes at a concrete diagnostic boundary, after 1,328 retained passed cases
and zero failed/error cases. This is not a full-suite pass; the complete core
sanitizer result remains a certified-runner/time-profile task. Receipt:
`docs/largefile-task-receipts/R03-libclamav-full-asan-timeout-2026-09-13.md`.

R03 full `libclamav` Release integration (2026-09-13 UTC): the existing ARM64
Release tree was reconfigured and rebuilt against the current 1,697-entry
source manifest (`ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`),
then its complete `libclamav` CTest target passed 1/1 in 89.73 seconds. The
underlying suite completed all 2,919 checks with zero failures and zero errors.
This is current-source development evidence only; the sanitizer aggregate
timeout, certified x86-64, exact 32-GiB/materialized resources, production
CVD/service, privileged fanotify, Sonic1, independent format-8, resource,
and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R03-libclamav-full-release-2026-09-13.md`.

R03 complete current-source Release CTest matrix (2026-09-13 UTC): after the
Release tree was reconfigured and rebuilt against the current manifest, all
28 registered targets passed in 182.03 seconds. This includes the complete
2,919-check `libclamav` suite, all large-file admission/protocol/resource
controls, Rust integration, `clamscan`, `clamd`, both milter targets,
`freshclam`, and `sigtool`. This is ARM64 development evidence only;
certified x86-64, exact 32-GiB/materialized resources, production CVD/service,
privileged fanotify, Sonic1, independent format-8, resource, and final
release qualification remain open. Receipt:
`docs/largefile-task-receipts/R03-current-source-release-ctest-2026-09-13.md`.

R06 OneNote spool-release assertion (2026-09-13 UTC): the current-source
production-linked `rust_onenote` over-cap corpus case now asserts that the
shared temporary ledger is zero after successful nested detection while a
nonzero temporary peak proves the parser and attachment spools were actually
used. The rebuilt ARM64 Release `check_clamav` binary passed the focused
`rust_onenote` TCase 4/4 with zero failures and errors. This is development
evidence only; certified x86-64, materialized full-size edges, sanitizer
coverage for this tightened case, production CVD/service, resource/fanotify,
Sonic1, and final release qualification remain open. No capability was
promoted. Receipt:
`docs/largefile-task-receipts/R06-onenote-spool-release-2026-09-13.md`.

R06 OneNote spool-release sanitizer revalidation (2026-09-13 UTC): after
reconfiguring the existing ARM64 `RelWithDebInfo` ASan/UBSan tree against the
current 1,697-entry source manifest, the production-linked `rust_onenote`
over-cap corpus case passed 4/4 with zero failures and errors. The focused
binary and CMake cache were source-bound to manifest
`c75877cc35ffc2d86a4a7c086cc2a51a80e026ec96a5e047ec223e98942246d9`, and no
sanitizer diagnostics were emitted. This remains development evidence only;
certified x86-64, exact 32-GiB/materialized resources, production CVD/service,
resource/fanotify, Sonic1, and final release qualification remain open. No
capability was promoted. Receipt:
`docs/largefile-task-receipts/R06-onenote-spool-release-asan-2026-09-13.md`.

R03 current-source Release matrix revalidation after R06 (2026-09-13 UTC):
the existing ARM64 Release tree was reconfigured and rebuilt against the
current 1,697-entry source manifest after the OneNote spool-release assertion
was added. The complete CTest matrix passed 28/28 in 187.23 seconds,
including the 2,919-check `libclamav` suite, all large-file controls and
verifiers, Rust, `clamscan`, `clamd`, `clamdscan`, both milter targets,
`freshclam`, and `sigtool`. This remains ARM64 development evidence only;
certified x86-64, exact 32-GiB/materialized resources, production CVD/service,
privileged fanotify, Sonic1, independent format-8, resource, and final
release qualification remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R03-current-source-release-ctest-r06-2026-09-13.md`.

R11 current-source Release service vertical slice (2026-09-13 UTC): the
freshly reconfigured ARM64 Release `clamd`/`clamdscan` build produced 36 live
R04 records across six structured report commands and six client modes, with
12 `COMPLETE`, 12 `DETECTION_TERMINATED`, and 12 `LIMIT_INCOMPLETE` outcomes.
Independent acceptance-record validation passed, and all clean/detection/
limit daemon lifecycles proved pre/post health, normal exit, and socket/PID
cleanup. This is small-fixture ARM64 development evidence only; exact
32-GiB/materialized service behavior, certified x86-64, production CVD,
privileged fanotify, milter, Sonic1, resource sidecars, and final release
qualification remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R11-development-service-vertical-slice-release-2026-09-13.md`.

R04 current-source Release `clamscan` vertical slice (2026-09-13 UTC): the
fresh Release scanner produced six live file/stdin records covering two
`COMPLETE`, two `DETECTION_TERMINATED`, and two `LIMIT_INCOMPLETE` outcomes.
Independent validation against the current case map and retained artifacts
passed. This is small-fixture ARM64 development evidence only; exact
32-GiB/materialized ingress, certified x86-64, production CVD, resource,
fanotify, Sonic1, and final release qualification remain open. No capability
was promoted. Receipt:
`docs/largefile-task-receipts/R04-development-clamscan-vertical-slice-release-2026-09-13.md`.

R03 source-bound revalidation after status snapshot correction (2026-09-13
UTC): correcting the maintained OneNote status wording changed the source
manifest, so the existing ARM64 Release and ASan/UBSan trees were both
reconfigured and rebuilt against the new 1,697-entry manifest
`1664c22ff783fd269c2c0e12e21ba81e05ce6c603fff66fe8a0530d68b87093d`. The
focused OneNote sanitizer test passed 4/4, and the complete current-source
Release matrix passed 28/28 in 174.02 seconds. Snapshot freshness and tracked
snapshot equality also passed. This remains development evidence only; the
certified x86-64, exact 32-GiB/materialized, production-CVD/service,
resource/fanotify, Sonic1, independent format-8, and final release gates
remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R03-source-rebound-status-snapshot-2026-09-13.md`.

R04/R11 current-source Release acceptance refresh (2026-09-13 UTC): after
rebinding the Release build to the current 1,697-entry source manifest, fresh
captures produced 36 service records (12 each `COMPLETE`,
`DETECTION_TERMINATED`, and `LIMIT_INCOMPLETE`) and six direct `clamscan`
records (two of each outcome). Both bundles independently passed the strict
acceptance-record verifier, and service lifecycle health/cleanup artifacts
were retained. This remains ARM64 small-fixture development evidence only;
exact 32-GiB/materialized, certified x86-64, production CVD, resource,
fanotify, Sonic1, and final release qualification remain open. No capability
was promoted. Receipt:
`docs/largefile-task-receipts/R04-R11-current-source-release-acceptance-refresh-2026-09-13.md`.

R03 Sonic3 MCP-SSH connectivity check (2026-09-13 UTC): host discovery and
the supplied `sonic3-sudo` profile description succeeded, and the exact
read-only `docker ps -a` command was policy-allowed by preview. Three live
attempts then timed out during SSH connect at 20, 30, and 30 seconds,
respectively, all with `remote_started=false`. No remote command, source transfer, or
filesystem mutation occurred. Sonic3 qualification is therefore blocked by
connectivity from the current MCP-SSH deployment, independently of the local
ARM64/capacity blocker. Receipt:
`docs/largefile-task-receipts/R03-sonic3-mcp-ssh-connectivity-2026-09-13.md`.

R03/R11 materialized-edge capacity check (2026-09-13 UTC): the current host
has 35 GiB free on the worktree volume, the container mount has 13 GiB free,
the container overlay is full, available container memory is 1.8 GiB with
swap already in use, and the only Docker context is ARM64 `desktop-linux`.
The roadmap's certified runner contract requires Linux x86-64, at least 48 GiB
effective memory, and 68 GiB free disk-backed temporary space. No materialized
32-GiB fixture was created. This is a concrete blocker for full-size,
materialized, resource, fanotify, and final qualification evidence; it does
not invalidate the ARM64 development build. Receipt:
`docs/largefile-task-receipts/R03-materialized-edge-capacity-check-2026-09-13.md`.

R13 resource-capture fail-closed correction and revalidation (2026-09-13
UTC): `largefile_acceptance_resource_capture.py` now terminates and rejects a
capture when a required sampler fails while the wrapped command remains alive,
and phase-protocol reads reject symlink replacement. Five focused host
regressions passed. Both current ARM64 build trees were reconfigured and
rebuilt against source manifest
`0cd222db4377ba8d53519d743cf75f2b5f0cdcf504f0223d7551de5ab9213439`; the full
Release CTest matrix passed 28/28 in 180.64 seconds, and the focused
ASan/UBSan resource-capture target passed 1/1 with no sanitizer diagnostics.
This strengthens evidence integrity but does not qualify any capability.
Receipt:
`docs/largefile-task-receipts/R13-resource-capture-fail-closed-2026-09-13.md`.

R03 current-source Rust integration ASan/UBSan revalidation (2026-09-13
UTC): the standalone `libclamav_rust` CTest target passed 159 Rust tests in
2.44 seconds against the current 1,697-entry source manifest, with no ASan,
UBSan, LeakSanitizer, or runtime-error diagnostics in retained logs. This is
ARM64 development evidence only; certified x86-64, full-size/materialized,
production CVD/service, resource/fanotify, Sonic1, independent format-8, and
final release evidence remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R03-rust-integration-asan-current-2026-09-13.md`.

R03 current-source application-facing ASan/UBSan CTest revalidation
(2026-09-13 UTC): the current ARM64 sanitizer build passed all 26 selected
application-facing targets in 515.72 seconds, including 21 large-file and
release-control targets, both milter targets, `clamscan`, `clamd`,
`freshclam`, and `sigtool`. Retained logs contained no ASan, UBSan,
LeakSanitizer, or runtime-error diagnostics. This is development evidence
only; certified x86-64, full-size/materialized, production CVD/service,
resource/fanotify, Sonic1, independent format-8, and final release evidence
remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R03-application-facing-asan-ctest-current-2026-09-13.md`.

R09 current-source sanitizer required-unsupported suite (2026-09-13 UTC):
the reconfigured ARM64 ASan/UBSan `check_clamav` binary, bound to source
manifest `1664c22ff783fd269c2c0e12e21ba81e05ce6c603fff66fe8a0530d68b87093d`,
passed all 57 cases in the `required_unsupported` group with zero failures or
errors. Retained sanitizer stderr contained no ASan, UBSan, LeakSanitizer, or
runtime-error diagnostics. This strengthens development coverage for the
seven R09 rows but does not qualify them: certified x86-64, full-size and
materialized edges, production CVD/service, resource/fanotify, Sonic1,
independent format-8 bytecode, and final release evidence remain required.
No capability was promoted. Receipt:
`docs/largefile-task-receipts/R09-required-unsupported-check-suite-asan-current-2026-09-13.md`.

R03/R10/R13 current-source build revalidation after structured-report test
correction (2026-09-13 UTC): the child fixture now ignores the expected
peer-close `SIGPIPE`, and the derived large-file inventory was regenerated
from the repository inventory script. The current 1,697-entry source manifest
(`8bc6ca7cb824cfd13e3e6980a79d053503d9df9a475e6d90f23c0392f82aeb34`) passed
the source guards. The ARM64 Release matrix passed 28/28 in 193.94 seconds;
the current-source ARM64 ASan/UBSan application/control subset passed 27/27
in 500.58 seconds. The only excluded sanitizer target was the known full
`libclamav` timeout at 1,200.98 seconds, with no sanitizer diagnostics. This
is development verification only: no capability was promoted, and certified
x86-64, exact 32-GiB materialized edges, production CVD/service, privileged
fanotify, independent format-8/JIT, and final readiness remain open. Receipt:
`docs/largefile-task-receipts/R03-current-source-build-revalidation-2026-09-13.md`.

R01 provenance revalidation (2026-09-13 UTC): the snapshot regression suite
passed 13/13, tracked snapshot freshness passed, and the current Git-mode
source manifest remained 1,697 files with SHA-256
`8bc6ca7cb824cfd13e3e6980a79d053503d9df9a475e6d90f23c0392f82aeb34`, matching
the current Release and ASan/UBSan build identities. This confirms the
dashboard/source-manifest provenance contract after the latest worktree
changes; no capability status or release-readiness result changed. Receipt:
`docs/largefile-task-receipts/R01-provenance-revalidation-2026-09-13.md`.

R05 streaming ZIP late-member fixture (2026-09-13 UTC): the deterministic
ZIP generator now writes payloads in bounded 1-MiB chunks, accepts explicit
large-run sizes, and emits ZIP64 when required. Its independent oracle now
uses bounded random-access metadata reads and streams the target member for
CRC and marker validation. The focused regression passed 6/6, including a
parameterized 2-MiB prefix / 1-MiB target-prefix round trip and a synthetic
ZIP64 directory round trip; the full source-guard sweep passed. This is
fixture-preparation evidence only: no
roadmap-scale materialized ZIP was created locally, no capability was
promoted, and certified runner/full-family evidence remains open. Receipt:
`docs/largefile-task-receipts/R05-streaming-zip-fixture-2026-09-13.md`.

R03 current-source Release application smoke (2026-09-13 UTC): the existing
ARM64 Release tree was reconfigured and rebuilt against the current 1,697-entry
source manifest (`7c9e98e508dea7060cf515f952d734b311bd5be2bfeb3816b1cbcfb7a0eebf00`).
The Release `clamscan` returned `OK` for a clean repository file and the exact
`ClamAV-Test-File.UNOFFICIAL FOUND` result for the checked-in known-test-file
fixture. This is local development smoke evidence only; no capability was
promoted and full-size/certified/release evidence remains open. Receipt:
`docs/largefile-task-receipts/R03-current-source-release-smoke-2026-09-13.md`.

R03 current-source Release CTest after R05 (2026-09-13 UTC): the
source-rebound ARM64 Release matrix passed 28/28 targets in 189.04 seconds,
including `libclamav`, all large-file controls, the registered ZIP late-member
test, Rust, `clamscan`, `clamd`, `freshclam`, `sigtool`, clamdscan controls,
and both milter targets. This is development verification only; exact
32-GiB/materialized, certified x86-64, production-CVD/service,
privileged-fanotify, independent-format-8, and final release evidence remain
open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R03-current-source-release-ctest-r05-2026-09-13.md`.

R03 current-source ASan/UBSan CTest after R05 (2026-09-13 UTC): the
source-rebound ARM64 sanitizer matrix passed 27/27 runnable targets in 500.89
seconds with no ASan, UBSan, LeakSanitizer, or runtime-error diagnostics,
including the ZIP64 regression and application/control targets. The complete
`libclamav` sanitizer target remains explicitly excluded after its known
1,200-second timeout and is not represented as a pass. Certified x86-64,
exact 32-GiB/materialized, production-CVD/service, fanotify, Sonic1,
independent-format-8, and final release evidence remain open. No capability
was promoted. Receipt:
`docs/largefile-task-receipts/R03-current-source-asan-ctest-r05-2026-09-13.md`.

R03 ASan/UBSan suite-slice diagnostics (2026-09-13 UTC): current-source
focused Check groups passed `egg_map` 16/16, `7z` 28/28, `rust_onenote` 4/4,
`zip` 19/19, and `pdf` 24/24. These groups produced no failed or errored
checks and keep the ASan tree bound to source manifest `4b6322…`. The full
aggregate `libclamav` timeout remains unresolved and is not relabelled as a
pass; certified runner/profile and final release evidence remain open. No
capability was promoted. Receipt:
`docs/largefile-task-receipts/R03-asan-suite-slice-diagnostics-2026-09-13.md`.

R03 current-source `cl_api` ASan/UBSan slice (2026-09-13 UTC): with
`CVD_CERTS_DIR` explicitly bound to the mounted source certificate directory,
the Check runner completed all 528 `cl_api` checks with zero failures and zero
errors. Retained output contained no ASan, UBSan, LeakSanitizer, or
runtime-error diagnostics. This is ARM64 development evidence only; the
aggregate `libclamav` sanitizer timeout, certified x86-64, exact
32-GiB/materialized edges, production CVD/service, privileged fanotify,
Sonic1, independent format-8, and final release evidence remain open. No
capability was promoted. Receipt:
`docs/largefile-task-receipts/R03-asan-cl-api-current-2026-09-13.md`.

R03 current-source API ASan/UBSan slices (2026-09-13 UTC): with the same
explicit certificate-directory binding, `cl_callback_api` passed 4/4 and
`cl_scan_api` passed 836/836, both with zero failures or errors and no retained
ASan, UBSan, LeakSanitizer, or runtime-error diagnostics. A zero-check
`cl_load` selection was not counted. This is ARM64 development evidence only;
the aggregate `libclamav` sanitizer timeout, certified x86-64, exact
32-GiB/materialized edges, production CVD/service, privileged fanotify,
Sonic1, independent format-8, and final release evidence remain open. No
capability was promoted. Receipt:
`docs/largefile-task-receipts/R03-asan-api-slices-current-2026-09-13.md`.

R08 current-source parser ASan/UBSan slices (2026-09-13 UTC): `arj_map` 8/8,
`arj` 14/14, `xar_metadata` 3/3, `hwp3_map` 3/3, `hwp3` 27/27, `xar` 19/19,
`arjsfx` 5/5, and `mspack_map` 8/8 passed for 87 checks total, with zero
failures/errors and no sanitizer diagnostics. This is ARM64 development
evidence only; capability-specific R04 records, full-size/materialized
fixtures, certified x86-64, production CVD/service, resource/fanotify,
independent format-8, Sonic1, and final release evidence remain open. No
capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-asan-parser-slices-current-2026-09-13.md`.

R08 current-source container and mail ASan/UBSan slices (2026-09-13 UTC):
`hwpole2_map` 5/5, `hwpole2_corpus` 1/1, `xdp_map` 5/5, `xdp` 3/3,
`mail_api` 4/4, `mail_map` 2/2, `mail_partial` 1/1, and `macho_map` 3/3
passed for 24 checks total, with zero failures/errors and no sanitizer
diagnostics. This is ARM64 development evidence only; capability-specific R04
records, full-size/materialized fixtures, certified x86-64, production
CVD/service, resource/fanotify, independent format-8, Sonic1, and final
release evidence remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-asan-container-mail-slices-current-2026-09-13.md`.

R08 current-source map, boundary, and cleanup ASan/UBSan slices (2026-09-13
UTC): `pdf_map` 7/7, `pdf_corpus` 1/1, `xdp_corpus` 1/1, `macho_timeout` 2/2,
`macho_boundary` 2/2, `dmg_map` 12/12, `7z_map` 4/4, `7z_cleanup` 1/1, and
`compressed_cleanup` 1/1 passed for 31 checks total, with zero
failures/errors and no sanitizer diagnostics. This is ARM64 development
evidence only; capability-specific R04 records, full-size/materialized
fixtures, certified x86-64, production CVD/service, resource/fanotify,
independent format-8, Sonic1, and final release evidence remain open. No
capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-asan-map-boundary-cleanup-slices-current-2026-09-13.md`.

R03 current-source Release CTest after provenance rebind (2026-09-13 UTC):
the Release tree was reconfigured/rebuilt so its CMake and build manifest
match the current source manifest `4b6322…`. Targets 1–25 passed in the first
CTest invocation; the disposable container then reached its configured
one-hour sleep lifetime with `oom=false` while entering `clamd`. After
restarting the same container, targeted `clamd`, `freshclam`, and `sigtool`
passed 3/3. Combined target coverage is 28/28, with no source/build option
changes during the rebind. This remains ARM64 development evidence only; no
capability was promoted. Receipt:
`docs/largefile-task-receipts/R03-current-source-release-ctest-r07-2026-09-13.md`.

R04 current-source Release `clamscan` vertical slice after provenance rebind
(2026-09-13 UTC): six fresh records passed independent validation against
source manifest `4b6322…`, covering clean, exact detection, and MaxFileSize
limit outcomes over file and stdin ingress (two records per outcome). This is
small-fixture ARM64 development evidence only; exact 32-GiB/materialized,
certified x86-64, production CVD/service, resource, fanotify, Sonic1, and
final release evidence remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R04-development-clamscan-vertical-slice-current-r07-2026-09-13.md`.

R10/R11 current-source Release service capture after provenance rebind
(2026-09-13 UTC): fresh `clamd`/`clamdscan` development capture produced 36
records bound to source manifest `4b6322…`: 12 `COMPLETE`, 12
`DETECTION_TERMINATED`, and 12 `LIMIT_INCOMPLETE` across all six structured
daemon report commands and six client modes. All retained lifecycle health and
cleanup checks passed, and the standalone acceptance verifier passed. This is
small-fixture ARM64 development evidence only; exact 32-GiB/materialized,
certified x86-64, production CVD, resource, fanotify, Sonic1, independent
format-8, and final release evidence remain open. No capability was promoted.
Receipt:
`docs/largefile-task-receipts/R10-development-service-current-r07-2026-09-13.md`.

R08 current-source OLE, VBA, MSExpand, NSIS, and SWF ASan/UBSan slices
(2026-09-13 UTC): `ole2_map` 7/7, `ole2_xlm` 3/3, `vba` 3/3, `msexpand` 8/8,
`msexpand_map` 2/2, `nulsft` 8/8, `nulsft_map` 2/2, `nulsft_corpus` 1/1,
`swf` 16/16, `swf_map` 3/3, `swf_api` 1/1, and `swf_corpus` 2/2 passed for
56 checks total, with zero failures/errors and no sanitizer diagnostics. This
is ARM64 development evidence only; capability-specific R04 records,
full-size/materialized fixtures, certified x86-64, production CVD/service,
resource/fanotify, independent format-8, Sonic1, and final release evidence
remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-asan-ole-swf-slices-current-2026-09-13.md`.

R08 current-source executable parser ASan/UBSan slices (2026-09-13 UTC):
`elf_map` 17/17, `elf_corpus` 1/1, `elf` 4/4, `pe32plus_common` 8/8,
`pe_map` 18/18, `pe_corpus` 1/1, `macho` 12/12, `macho_fat` 3/3,
`macho_sections` 1/1, and `macho_corpus` 2/2 passed for 67 checks total,
with zero failures/errors and no sanitizer diagnostics. This is ARM64
development evidence only; capability-specific R04 records,
full-size/materialized fixtures, certified x86-64, production CVD/service,
resource/fanotify, independent format-8, Sonic1, and final release evidence
remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-asan-executable-parser-slices-current-2026-09-13.md`.

R08 current-source filesystem/container ASan/UBSan slices (2026-09-13 UTC):
TAR/CPIO groups passed 39/39, ISO groups 20/20, UDF groups 15/15 (the base
`udf` selector contained zero checks), partition-map 5/5, GPT 9/9, and MBR
12/12, for 100 substantive checks total. All completed with zero
failures/errors and no sanitizer diagnostics. This is ARM64 development
evidence only; capability-specific R04 records, full-size/materialized
fixtures, certified x86-64, production CVD/service, resource/fanotify,
independent format-8, Sonic1, and final release evidence remain open. No
capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-asan-filesystem-container-slices-current-20260913.md`.

R08 current-source graphics and image ASan/UBSan slices (2026-09-13 UTC):
graphics groups passed 13/13, GIF groups 18/18, PNG groups 10/10, TIFF groups
17/17, and JPEG groups 15/15, for 73 checks total. All completed with zero
failures/errors and no sanitizer diagnostics. This is ARM64 development
evidence only; capability-specific R04 records, full-size/materialized
fixtures, certified x86-64, production CVD/service, resource/fanotify,
independent format-8, Sonic1, and final release evidence remain open. No
capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-asan-graphics-image-slices-current-2026-09-13.md`.

R08 current-source archive and compression ASan/UBSan slices (2026-09-13
UTC): DMG/HFS+ groups passed 41/41, SIS 8/8, AutoIt 11/11, ZIP-SFX/RAR/CAB
79/79, XZ 6/6, and BinHex/MyDoom/BZip2 35/35, for 120 checks total. All
completed with zero failures/errors and no sanitizer diagnostics. This is
ARM64 development evidence only; capability-specific R04 records,
full-size/materialized fixtures, certified x86-64, production CVD/service,
resource/fanotify, independent format-8, Sonic1, and final release evidence
remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-asan-archive-compression-slices-current-20260913.md`.

R06/R08 current-source API, text, and Rust ASan/UBSan slices (2026-09-13
UTC): API/fmap/CVD groups passed 24/24, text/document groups 54/54, and
Rust/MSXML groups 27/27, for 105 checks total. All completed with zero
failures/errors and no sanitizer diagnostics. This is ARM64 development
evidence only; capability-specific R04 records, full-size/materialized
fixtures, certified x86-64, production CVD/service, resource/fanotify,
independent format-8, Sonic1, and final release evidence remain open. No
capability was promoted. Receipt:
`docs/largefile-task-receipts/R06-R08-asan-api-text-rust-slices-current-20260913.md`.

R06/R08 current-source document and mail ASan/UBSan slices (2026-09-13 UTC):
TNEF groups passed 23/23, HWP/HWPML groups 14/14, RIFF groups 11/11, and the
broader mail group 16/16, for 59 checks total. All completed with zero
failures/errors and no sanitizer diagnostics. This is ARM64 development
evidence only; capability-specific R04 records, full-size/materialized
fixtures, certified x86-64, production CVD/service, resource/fanotify,
independent format-8, Sonic1, and final release evidence remain open. No
capability was promoted. Receipt:
`docs/largefile-task-receipts/R06-R08-asan-document-mail-slices-current-20260913.md`.

R08 current-source XAR, SFX, and Office-entry ASan/UBSan slices (2026-09-13
UTC): XAR passed 7/7, APM 12/12, 7-Zip SFX 4/4, IShield SFX/map 5/5,
OLE10/PPT/OOXML entries 19/19, and binary-data 1/1, for 48 substantive
checks total. The `digital` and `assorted functions` selectors were empty.
All completed with zero failures/errors and no sanitizer diagnostics. This is
ARM64 development evidence only; capability-specific R04 records,
full-size/materialized fixtures, certified x86-64, production CVD/service,
resource/fanotify, independent format-8, Sonic1, and final release evidence
remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-asan-xar-sfx-office-slices-current-20260913.md`.

R08/R09 current-source broad ASan/UBSan suite slices (2026-09-13 UTC):
`mspack` 8/8, `ole2` 24/24, `pe` 16/16, `parser_regressions` 4/4, and
`required_unsupported` 57/57 passed for 109 checks total, with zero
failures/errors and no sanitizer diagnostics. The complete aggregate
`libclamav` sanitizer timeout remains separately unresolved and is not
relabeled as a pass. This is ARM64 development evidence only; capability-
specific R04 records, full-size/materialized fixtures, certified x86-64,
production CVD/service, resource/fanotify, independent format-8, Sonic1, and
final release evidence remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-asan-broad-suite-slices-current-20260913.md`.

R03 large-file qualification platform gate (2026-09-13 UTC): the existing
ARM64 ASan build's `largefile_qualification` selector contained zero checks
because the dedicated option is off. A separate out-of-tree ASan/UBSan
configuration with `ENABLE_LARGE_FILE_QUALIFICATION_TEST=ON` failed closed at
CMake with the repository's explicit restriction to the qualified Linux
x86-64 profile. The enabled Mach-O unsupported-policy slice passed 2/2 with no
sanitizer diagnostics. No platform guard was bypassed and no capability was
promoted. Receipt:
`docs/largefile-task-receipts/R03-largefile-qualification-platform-gate-2026-09-13.md`.

R03/R10 current-source Release application smoke (2026-09-13 UTC): the
rebuilt Release `clamscan` reported `ClamAV 1.5.3-largefile-devel`, returned
`OK` for a clean repository README, and returned the expected
`ClamAV-Test-File.UNOFFICIAL FOUND` for the repository ZIP test fixture using
the explicitly bound test certificate directory. An initial missing-certs
invocation failed closed as expected and was not counted as application
evidence. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R03-current-source-release-application-smoke-2026-09-13.md`.

R06 current-source Release OneNote reader parity (2026-09-13 UTC): the
production-linked Release `rust_onenote` group passed 4/4, including the
logical input above the former 256-MiB whole-input cap and reader-backed
attachment detection with zero residual temporary charge. This closes the
local Release-side parity gap for the bounded reader implementation; it is
still ARM64 development evidence and no capability was promoted. Receipt:
`docs/largefile-task-receipts/R06-onenote-reader-release-parity-2026-09-13.md`.

R09 current-source Release required-parser policy parity (2026-09-13 UTC):
the complete `required_unsupported` group passed 57/57, covering the seven
in-scope rows for RAR/RAR-SFX, ignored types, compiled Python, AI-model
parsing, and fuzzy-image admission/matching. This closes the local Release
parity gap alongside the existing ASan/UBSan result; no capability was
promoted. Receipt:
`docs/largefile-task-receipts/R09-required-parser-policy-release-parity-2026-09-13.md`.

R03 current-source build rebind after working-tree documentation changes
(2026-09-13 UTC): the existing ARM64 Release and ASan/UBSan trees were
reconfigured and rebuilt against source-manifest
`12aecbdf…`; all targets built successfully. Release application smoke,
`rust_onenote` 4/4, and `required_unsupported` 57/57 passed, with the same
results in ASan/UBSan for the two focused groups. The explicit missing-default-
database invocation failed closed and was not counted. This is development
evidence only; no capability was promoted. Receipt:
`docs/largefile-task-receipts/R03-current-source-rebind-2026-09-13.md`.

R03 current-source Release CTest revalidation after the provenance rebind
(2026-09-13 UTC): the full application matrix passed 28/28 in 194.94 seconds
against source-manifest `12aecbdf…`. This included `libclamav`, Rust,
clamscan, clamd, clamdscan, milter, freshclam, sigtool, and all large-file
controls. No test failures or sanitizer diagnostics occurred; this remains
ARM64 development evidence only. Receipt:
`docs/largefile-task-receipts/R03-current-source-release-ctest-r08-2026-09-13.md`.

R11 current-source service vertical slice after the provenance rebind
(2026-09-13 UTC): fresh ARM64 Release `clamd`/`clamdscan` capture wrote 36
records, independently validated against the current case map, with 12 each
of `COMPLETE`, `DETECTION_TERMINATED`, and `LIMIT_INCOMPLETE` across the six
structured daemon report commands and six client modes. Lifecycle health and
cleanup remained bound and passing. This is ingress-only development evidence
and does not qualify parser rows or release readiness. Receipt:
`docs/largefile-task-receipts/R11-development-service-vertical-slice-current-rebind-2026-09-13.md`.

R04 runtime POC record-integrity hardening (2026-09-13 UTC): duplicate
`poc/results.tsv` rows are now rejected instead of being silently overwritten
by the runtime acceptance producer. The new regression passes and preserves
independent POC result binding for the file-edge detection case; no capability
was promoted. This is a local verifier improvement, not qualification evidence.

R04 resource-binding record-integrity hardening (2026-09-13 UTC): the
standalone resource sidecar binder now rejects duplicate acceptance-case rows
before mutating records, closing the same silent-overwrite class at the
resource-binding boundary. The new regression passes; no capability was
promoted.

R04 structured-report parsing hardening (2026-09-13 UTC): all current
acceptance/service report readers now share a strict JSON-object loader that
rejects duplicate keys before validation. This prevents a later duplicate
field from replacing an independently emitted status, completion, signature,
or offset. The shared regression passes; no capability was promoted.

The same strict loader now protects the service input identity documents, so a
duplicate `version` or `inputs` key cannot silently replace the recorded
fixture binding during qualification. Its regression passes; no capability was
promoted.

R04/R13 retained-proof parsing hardening (2026-09-13): the fanotify permission
and PCRE phase evidence verifiers now reject duplicate JSON keys through the
shared strict loader. New regressions passed alongside the shared loader
tests; this is verifier hardening only and does not promote an on-access or
PCRE capability. Receipt:
`docs/largefile-task-receipts/R04-r13-proof-duplicate-json-key-hardening-2026-09-13.md`.

R03 current-source rebind and application verification (2026-09-13 UTC): the
existing ARM64 Release and ASan/UBSan trees were rebuilt against the current
1,697-entry source manifest `bf4f97…`. Release CTest passed 28/28 and the
complete local large-file Python harness passed 172 tests with two
Linux-only skips on macOS. The aggregate ASan/UBSan `libclamav` target
reached its configured 1,200-second timeout without sanitizer diagnostics, so
the sanitizer suite remains incomplete rather than being reported as passed.
Receipt:
`docs/largefile-task-receipts/R03-current-source-rebind-r09-2026-09-13.md`.

R04 evidence-consumer JSON hardening (2026-09-13 UTC): service-input,
oversize-combiner, and clamscan-admission consumers now reject duplicate JSON
keys through the shared strict loader. The complete local large-file harness
passed 174 tests with two Linux-only allocation skips; no capability was
promoted. Receipt:
`docs/largefile-task-receipts/R04-evidence-consumer-json-hardening-2026-09-13.md`.

R03 current-source control rebind (2026-09-13 UTC): Release and ASan/UBSan
trees were rebuilt against source manifest `4ff626…`; the non-aggregate
control/frontend subsets passed 27/27 in each build, with no sanitizer
diagnostics. The aggregate ASan/UBSan `libclamav` result was not rerun after
the Python-only changes and remains incomplete under the prior documented
1,200-second timeout. Receipt:
`docs/largefile-task-receipts/R03-current-source-rebind-r10-2026-09-13.md`.

R08 current-source parser-family revalidation (2026-09-13 UTC): focused
current-source ARM64 Release and ASan/UBSan `cl_suite` cases passed 54/54 in
each build across ARJ compression/map, BinHex, MyDoom, BZip2, CAB SFX, SIS,
and InstallShield SFX paths. No sanitizer diagnostics were emitted. This is
development evidence only; complete parser corpus, certified Linux x86-64,
exact/materialized 32-GiB, production CVD/service, resource/fanotify, Sonic1,
independent format-8, and final release evidence remain open. No capability
was promoted. Receipt:
`docs/largefile-task-receipts/R08-parser-family-revalidation-current-20260913.md`.

R05 current-source sparse oversize admission attempt (2026-09-13 UTC): the
corrected 32-GiB daemon profile initialized the current ARM64 Release engine,
then failed closed at the explicit platform guard before service admission:
`certified large-file daemon admission is limited to Linux x86-64`. No live
FILDESREPORT result or capability evidence was counted. The exact probe remains
ready for the authorized certified Linux x86-64 runner. Receipt:
`docs/largefile-task-receipts/R05-arm64-oversize-admission-blocker-20260913.md`.

R08 current-source matcher/YARA revalidation (2026-09-13 UTC): production-
linked ARM64 Release and ASan/UBSan matcher slices passed 72/72 in each build,
covering AC/BM/PCRE/logical/hash/bytecode compatibility and YARA admission,
arena, VM, accounting, and deadline cases. No sanitizer diagnostics were
emitted. This is development evidence only; complete matcher/YARA corpus,
certified Linux x86-64, exact/materialized 32-GiB, production CVD/service,
resource/fanotify, Sonic1, independent format-8, and final release evidence
remain open. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-matcher-yara-revalidation-current-20260913.md`.

R06/R08 current-source Rust CTest revalidation (2026-09-13 UTC): the
repository-configured `libclamav_rust` target passed 1/1 in both Release and
ASan/UBSan builds using the locked AArch64 Rust test command. No sanitizer
diagnostics were emitted. This is development evidence only; certified Linux
x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify,
Sonic1, independent format-8, and final release evidence remain open. No
capability was promoted. Receipt:
`docs/largefile-task-receipts/R06-rust-reader-ctest-current-20260913.md`.

R03 aggregate ASan/UBSan duration revalidation (2026-09-13 UTC): the
repository-configured `libclamav` CTest target stopped at its generated
1,200-second Python cap. A direct invocation with `T=2400` and a
2,700-second aggregate allowance reached the same current-source
`cl_scan_api` callback region but stopped at 2,700.418 seconds. No ASan or
UBSan diagnostic was emitted; this remains incomplete ARM64 duration
evidence, not a pass or capability promotion. Certified Linux x86-64
aggregate evidence remains open. Receipt:
`docs/largefile-task-receipts/R03-asan-libclamav-aggregate-timeout-current-20260913.md`.

R03 aggregate-test timeout configurability (2026-09-13 UTC): the sanitizer
CTest environment no longer hard-codes its outer Python timeout. The new
positive-integer `CLAMAV_LIBCLAMAV_TEST_TIMEOUT` CMake cache setting defaults
to the prior 1,200 seconds and is propagated into generated CTest state, so a
slow qualification runner can select a larger explicit budget without
editing generated files or changing per-case scan deadlines. CMake
propagation, source guards, snapshot freshness, syntax, and the 601-row
acceptance-map check passed. No aggregate sanitizer pass was claimed; the
current ARM64 result remains incomplete at 2,700.418 seconds. Receipt:
`docs/largefile-task-receipts/R03-aggregate-test-timeout-configurable-20260913.md`.

R03 timeout-option follow-up verification (2026-09-13 UTC): the existing
current-source ASan `check_clamav` target rebuilt successfully; the four
acceptance/source controls covering the setting passed 4/4; and an isolated
`CLAMAV_LIBCLAMAV_TEST_TIMEOUT=0` configure failed closed with the expected
positive-integer diagnostic. This verifies the option's build integration and
validation only; the ARM64 aggregate sanitizer run remains incomplete and no
capability was promoted.

R06 OneNote object-group payload spooling (2026-09-13 UTC): stream-backed
modern OneNote `BinaryItem` payloads now use the existing private bounded
`ReaderBlob` spool and temporary-budget interface instead of materializing each
structural payload as a `Vec<u8>`. OneStore header and object-property parsing
now consumes those payloads through bounded readers. The current CMake
RelWithDebInfo consumer target rebuilt with ASan/UBSan flags; the vendored
parser suite passed 78/78; `rust_onenote` passed 4/4; and
`required_unsupported` passed 57/57. This remains ARM64 development evidence;
materialized late-child, certified x86-64, production, and release evidence
remain open. Receipt:
`docs/largefile-task-receipts/R06-object-group-payload-spooling-20260913.md`.

R06 OneNote object-group spool Release parity (2026-09-13 UTC): the current
source Release `check_clamav` target rebuilt and the focused `rust_onenote`
group passed 4/4. The complete configured Release CTest matrix then passed
28/28 in 274.99 seconds. This is ARM64 development parity only; no capability
was promoted and certified full-size, x86-64, production, resource/fanotify,
and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R06-onenote-object-group-release-parity-2026-09-13.md`.

R03/R06 current-source ASan/UBSan matrix after OneNote spooling
(2026-09-13 UTC): the fresh ARM64 `RelWithDebInfo` sanitizer build passed
27/27 configured CTest tests in 531.55 seconds with no sanitizer diagnostics;
the known long aggregate `libclamav` test was excluded and remains incomplete
at its documented duration limit. No capability was promoted. Receipt:
`docs/largefile-task-receipts/R03-current-source-asan-ctest-r06-object-spool-2026-09-13.md`.

R06 current-source nested OneNote spool-budget propagation (2026-09-13 UTC):
OneStore header and object-property parsing now opens spooled object-group
payloads with the originating private-spool directory and shared temporary
budget. The parser unit suite passed 79/79; the full ARM64 Release CTest
matrix passed 28/28 in 199.01 seconds; and the bounded ASan/UBSan matrix
passed 27/27 in 533.65 seconds with no sanitizer diagnostics. The aggregate
`libclamav` sanitizer target remains explicitly excluded and incomplete under
the established ARM64 duration limit. This is development evidence only; no
capability was promoted. Receipt:
`docs/largefile-task-receipts/R06-current-source-nested-spool-budget-2026-09-13.md`.

R06 current-source FSSHTTPB fragment spooling (2026-09-13 UTC): stream-backed
modern OneNote `DataElementFragment` payloads now use the bounded `ReaderBlob`
spool instead of materializing a declared chunk as `Vec<u8>`. The parser unit
suite passed 80/80; current Release and ASan/UBSan `check_clamav` targets
rebuilt; focused runtime/service evidence passed 2/2 in each build; and the
corrected source guard passed 1/1 in each build. Inventory freshness and
`git diff --check` passed. This is ARM64 development evidence only; no
capability was promoted and certified full-size, x86-64, production, and final
release evidence remain open. Receipt:
`docs/largefile-task-receipts/R06-current-source-data-element-fragment-spool-2026-09-13.md`.

R03/R06 current-source Release and sanitizer revalidation after fragment
spooling (2026-09-13 UTC): the complete ARM64 Release CTest matrix passed
28/28 in 192.61 seconds, and the bounded ASan/UBSan matrix passed 27/27 in
500.85 seconds with no sanitizer diagnostics; the known long aggregate
`libclamav` sanitizer test was excluded. Both `check_clamav` targets and the
80-test parser suite passed, with inventory, snapshot, source guards, and
`git diff --check` green. This is development evidence only; no capability was
promoted and certified x86-64, exact/materialized 32-GiB, production,
resource/fanotify, independent format-8, and final release evidence remain
open. Receipt:
`docs/largefile-task-receipts/R03-current-source-release-asan-ctest-r06-fragment-2026-09-13.md`.

R08 current-source ALZ empty-member MaxFiles accounting (2026-09-13 UTC): a
valid ALZ archive containing two zero-byte stored members previously returned
clean with `MaxFiles=2`, bypassing the inclusive root/child budget. The
scanner-facing descriptor ingress now charges zero-byte children, the Rust
ALZ size-budget fast path preserves valid empty stored members, and the ALZ
sink sends them through nested descriptor admission. The production-linked
Release regression passed 3/3 and the ASan/UBSan regression passed 2/2; source
guards, inventory freshness, and `git diff --check` also passed. A broader
current-source Release CTest attempt was not counted after the container
filesystem filled with generated temporary scan files; the build itself
completed. This remains ARM64 development evidence only, with no capability
promotion; certified x86-64, exact/materialized 32-GiB, production,
resource/fanotify, independent format-8, and final release evidence remain
open. Receipt:
`docs/largefile-task-receipts/R08-alz-empty-member-maxfiles-2026-09-13.md`.

R06 current-source legacy OneNote empty-attachment MaxFiles accounting
(2026-09-13 UTC): a valid legacy OneNote marker with two zero-length
attachments previously returned clean with `MaxFiles=2` because the legacy
attachment sink skipped the empty nested scan. The sink now routes empty
attachments through descriptor admission. The pre-fix false success was
reproduced; rebuilt ARM64 Release and ASan/UBSan `rust_onenote` slices passed
5/5 in each build, with no sanitizer diagnostics. Source guards, inventory
freshness, and `git diff --check` passed. No capability was promoted; certified
x86-64, exact/materialized 32-GiB, production, resource/fanotify,
independent format-8, and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R06-onenote-empty-attachment-maxfiles-2026-09-13.md`.

R08 current-source ZIP empty-member MaxFiles accounting (2026-09-13 UTC): the
ZIP catalogue loop skipped members with both compressed and uncompressed sizes
zero before shared nested admission. It now charges the logical child through
`cli_updatelimits(ctx, 0)` and fails visibly on a configured limit result. The
production-linked ARM64 Release and ASan/UBSan `zip` slices passed 20/20 in
each build with no sanitizer diagnostics; source guards, inventory freshness,
and `git diff --check` passed. No capability was promoted; certified x86-64,
exact/materialized 32-GiB, production, resource/fanotify, independent
format-8, and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R08-zip-empty-member-maxfiles-2026-09-13.md`.

R08 current-source AutoIt empty-member MaxFiles accounting (2026-09-13 UTC):
the EA05 and EA06 handlers skipped declared zero-byte members before shared
nested admission. Both formats now charge the logical child through
`cli_updatelimits(ctx, 0)` and fail visibly on a configured limit result. The
production-linked ARM64 Release and ASan/UBSan `autoit_map` slices passed
10/10 in each build with no sanitizer diagnostics; source guards, inventory
freshness, and `git diff --check` passed. No capability was promoted; certified
x86-64, exact/materialized 32-GiB, production, resource/fanotify, independent
format-8, and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R08-autoit-empty-member-maxfiles-2026-09-13.md`.

R08 current-source CPIO empty-member MaxFiles accounting (2026-09-13 UTC):
the old, ODC, newc, and CRC handlers skipped ordinary zero-length members
before shared nested admission. A shared CPIO admission helper now charges
each ordinary empty child through `cli_updatelimits(ctx, 0)` while leaving the
`TRAILER!!!` terminator non-counting. The production-linked ARM64 Release
slice passed 3/3 across the CPIO group, and the ASan/UBSan rerun passed 2/2
with leak detection disabled after a prior container exit-137; no sanitizer
diagnostics were emitted. Source guards, inventory freshness, and
`git diff --check` passed. No capability was promoted; certified x86-64,
exact/materialized 32-GiB, production, resource/fanotify, independent
format-8, and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R08-cpio-empty-member-maxfiles-2026-09-13.md`.

R08 current-source InstallShield empty-member MaxFiles accounting
(2026-09-13 UTC): the legacy InstallShield path skipped declared zero-length
embedded files before shared nested admission, both in the outer metadata
records and in the CAB-backed header file table. `is_dump_and_scan()` and
`is_parse_hdr()` now charge each empty logical child through
`cli_updatelimits(ctx, 0)` and fail visibly on a configured limit result. The
production-linked ARM64 Release and ASan/UBSan `ishield_map` slices passed
6/6 in each build with no sanitizer diagnostics; source guards, inventory
freshness, and `git diff --check` passed. No capability was promoted;
certified x86-64, exact/materialized 32-GiB, production, resource/fanotify,
independent format-8, and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R08-ishield-empty-member-maxfiles-2026-09-13.md`.

R08 current-source NSIS empty-member MaxFiles accounting (2026-09-13 UTC):
non-solid NSIS members now charge declared zero-byte logical children through
shared nested admission, while the archive CRC trailer remains excluded. The
solid path also decodes zero-byte member headers before applying size-based
byte limits; no synthetic solid fixture was retained because it was
incompatible with the bundled NSIS decoder. The production-linked ARM64
Release and ASan/UBSan `nulsft` slices passed 1/1 in each build with no
sanitizer diagnostics; source guards, inventory freshness, and
`git diff --check` passed. No capability was promoted; certified x86-64,
exact/materialized 32-GiB, production, resource/fanotify, independent
format-8, and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R08-nsis-empty-member-maxfiles-2026-09-13.md`.

R08 current-source SIS empty-member MaxFiles accounting (2026-09-13 UTC): the
legacy Symbian SIS language-member loop skipped declared zero-byte variants
before shared nested admission. It now charges each empty language variant
through `cli_updatelimits(ctx, 0)` and retains configured-limit failures as
fail-visible parser results. The production-linked ARM64 Release and
ASan/UBSan `sis_member` slices passed 1/1 in each build with no sanitizer
diagnostics; source guards, inventory freshness, and `git diff --check` passed.
No capability was promoted; certified x86-64, exact/materialized 32-GiB,
production, resource/fanotify, independent format-8, and final release
evidence remain open. Receipt:
`docs/largefile-task-receipts/R08-sis-empty-member-maxfiles-2026-09-13.md`.

R08 current-source 7-Zip empty-member MaxFiles accounting (2026-09-13 UTC):
the 7-Zip zero-output member path extracted logical empty files without
passing them through nested descriptor admission. It now routes empty output
through `cli_magic_scan_desc_type_reserved()`, preserving directory skips
while charging empty files to inclusive `MaxFiles` and cache invalidation.
The production-linked ARM64 Release and ASan/UBSan `7z` slices passed 29/29
cases in each build with no sanitizer diagnostics; source guards, inventory
freshness, and `git diff --check` passed. No capability was promoted;
certified x86-64, exact/materialized 32-GiB, production, resource/fanotify,
independent format-8, and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R08-7z-empty-member-maxfiles-2026-09-13.md`.

R08 current-source HFS+ empty catalog-file MaxFiles accounting (2026-09-13
UTC): ordinary HFS+ catalog files with both data and resource forks empty
were recognized but skipped before shared child admission. The catalog walker
now charges that logical child through `cli_updatelimits(ctx, 0)` while
leaving directories and compressed-file handling on their existing paths. The
production-linked ARM64 Release and ASan/UBSan `hfs_map` slices passed 1/1 in
each build with no sanitizer diagnostics; source guards, inventory freshness,
and `git diff --check` passed. No capability was promoted; certified x86-64,
exact/materialized 32-GiB, production, resource/fanotify, independent
format-8, and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R08-hfsplus-empty-catalog-file-maxfiles-2026-09-13.md`.

R08 current-source UDF empty-file MaxFiles accounting (2026-09-13 UTC): valid
regular UDF files with no allocation descriptors, or only zero-length
extents, returned clean without shared nested admission. Both paths now
charge the logical child through `cli_updatelimits(ctx, 0)` and preserve
fail-visible limit results. The production-linked ARM64 Release and
ASan/UBSan `udf_corpus` slices passed 1/1 in each build with no sanitizer
diagnostics; source guards, inventory freshness, and `git diff --check`
passed. No capability was promoted; certified x86-64, exact/materialized
32-GiB, production, resource/fanotify, independent format-8, and final
release evidence remain open. Receipt:
`docs/largefile-task-receipts/R08-udf-empty-file-maxfiles-2026-09-13.md`.

R08 current-source empty nested-range MaxFiles accounting (2026-09-13 UTC):
the shared nested-fmap helper returned a zero-byte nested range as a clean
no-match without consuming a logical-child slot; it now routes the range
through `cli_updatelimits(ctx, 0)` before clean-result reconciliation. The
production-linked ARM64 Release and ASan/UBSan `hwpole2_map` slices passed
1/1 in each build with no sanitizer diagnostics; source guards, inventory
freshness, and `git diff --check` passed. No capability was promoted;
certified x86-64, exact/materialized 32-GiB, production, resource/fanotify,
independent format-8, and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R08-empty-nested-range-maxfiles-2026-09-13.md`.

R08 current-source TNEF empty-attachment MaxFiles accounting (2026-09-13
UTC): the TNEF loop previously treated every zero-length attribute as
metadata and skipped attachment-level `attAttachData` before creating or
admitting a logical child. Valid zero-length attachment data now consumes one
inclusive MaxFiles slot through the shared admission helper, while message
metadata remains non-child and still consumes its checksum. The Release and
ASan/UBSan production-linked `tnef` slices passed 19/19 in each build; the
initial Release assertion failure correctly exposed the canonical MaxFiles
reason, and the corrected regression verifies both rejection and exact
completion. No sanitizer diagnostics were emitted. Source guards, inventory
freshness, and `git diff --check` passed; no capability was promoted. Certified
x86-64, exact/materialized
32-GiB, production, resource/fanotify, independent format-8, and final
release evidence remain open. Receipt:
`docs/largefile-task-receipts/R08-tnef-empty-attachment-maxfiles-2026-09-13.md`.

R08 current-source TNEF empty-attachment-title format handling (2026-09-13
UTC): a zero-length attachment-level `attAttachTitle` attribute was accepted
as clean before reaching the existing attachment string validation. The loop
now rejects that malformed case with `CL_EFORMAT`, records the explicit
incomplete reason `TNEF attachment title is empty`, and preserves cache taint.
The new regression reproduced the pre-fix clean result, then the corrected
production-linked ARM64 Release and ASan/UBSan `tnef` slices passed 20/20 in
each build with no sanitizer diagnostics. Source guards, inventory freshness,
and `git diff --check` passed; no capability was promoted. Certified x86-64,
exact/materialized 32-GiB, production, resource/fanotify, independent
format-8, and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R08-tnef-empty-title-format-2026-09-13.md`.

R08 current-source PDF empty extracted-object MaxFiles accounting (2026-09-13
UTC): `pdf_extract_obj()` previously skipped descriptor admission whenever a
successfully materialized object decoded to zero bytes, and an empty PDF
stream returned before that shared path entirely. Both paths now route the
empty output through descriptor admission so the logical child consumes the
inclusive MaxFiles slot and preserves cache invalidation; zero-byte output
continues to skip PDF bytecode/content hooks that require a mappable payload.
The new regressions first reproduced the uncounted raw-object path, then
covered the empty-stream path; the corrected production-linked ARM64 Release
and ASan/UBSan `pdf` slices passed 26/26 in each build with no sanitizer
diagnostics. Source guards, inventory freshness, and `git diff --check` passed,
and no capability was promoted. Certified x86-64, exact/materialized 32-GiB, production,
resource/fanotify, independent format-8, Sonic1, and final parser/release
evidence remain open. Receipt:
`docs/largefile-task-receipts/R08-pdf-empty-object-maxfiles-2026-09-13.md`.

R03 current-source Release control revalidation (2026-09-13 UTC): the
current working tree rebuilt successfully in the retained ARM64 container;
the configured Release matrix excluding only the documented aggregate
`libclamav` timeout passed 27/27 in 149.63 seconds. The pass includes all
large-file controls, Rust integration, milter, `clamscan`, `clamd`, freshclam,
and sigtool; bounded ARJ slices also passed 14/14, 8/8, 2/2, and 5/5. This is
current-source development evidence only. The aggregate ARM64 `libclamav`
run remains incomplete, and certified x86-64, exact/materialized 32-GiB,
production CVD/service, resource/fanotify, independent format-8, Sonic1,
and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R03-current-source-release-controls-revalidation-2026-09-13.md`.

R03 current-source ASAN/UBSAN control revalidation (2026-09-13 UTC): the
current working tree rebuilt successfully in the retained ARM64 container;
the bounded matrix excluding only the documented aggregate `libclamav`
timeout passed 27/27 in 533.43 seconds with no sanitizer diagnostics in the
CTest or unit-test stderr artifacts. The pass includes all large-file
controls, Rust integration, milter, `clamscan`, `clamd`, freshclam, and
sigtool. This is current-source development evidence only. The aggregate
ARM64 `libclamav` run remains incomplete, and certified x86-64,
exact/materialized 32-GiB, production CVD/service, resource/fanotify,
independent format-8, Sonic1, and final release evidence remain open. Receipt:
`docs/largefile-task-receipts/R03-current-source-asan-controls-revalidation-2026-09-13.md`.

R08 current-source HTML CSS empty-child MaxFiles accounting (2026-09-13 UTC):
the shared Rust reader-to-temporary-spool helper previously returned clean
without descriptor admission when a decoded child was zero bytes. It now
routes empty reader output through the same admission path as non-empty
children, preserving inclusive MaxFiles accounting and cache taint. The
production-linked current-source ARM64 Release and ASan/UBSan HTML regression
both passed 1/1 with no sanitizer diagnostic; source guards, snapshot
freshness, regenerated inventory, and `git diff --check` passed. No capability
was promoted; exact/materialized 32-GiB, certified x86-64, production
CVD/service, resource/fanotify, Sonic1, independent format-8, and final
release qualification remain open. Receipt:
`docs/largefile-task-receipts/R08-html-css-empty-child-maxfiles-2026-09-13.md`.

R08 current-source MSXML streaming empty-Base64 MaxFiles accounting (2026-09-13 UTC): the streaming MSXML Base64 path previously skipped nested descriptor admission when a recognized element decoded to zero bytes. Every created Base64 spool now reaches the existing callback or descriptor-admission path, preserving inclusive MaxFiles accounting and cache taint for empty and whitespace-only values. The production-linked current-source ARM64 Release and ASan/UBSan regression both passed 1/1 with no sanitizer diagnostic; source guards, snapshot freshness, regenerated inventory, and `git diff --check` passed. No capability was promoted; exact/materialized 32-GiB, certified x86-64, production CVD/service, resource/fanotify, Sonic1, independent format-8, and final release qualification remain open. Receipt: `docs/largefile-task-receipts/R08-msxml-empty-base64-maxfiles-2026-09-13.md`.

R08 current-source MSXML empty-callback MaxFiles accounting (2026-09-13 UTC): the streaming MSXML callback path previously skipped a recognized callback element when it had no character data, even though its temporary spool had been created. Every created callback spool now reaches the callback and its owning descriptor-admission path, preserving inclusive MaxFiles accounting and cache taint for empty values. The production-linked current-source ARM64 Release and ASan/UBSan regression both passed 1/1 with no sanitizer diagnostic; source guards, snapshot freshness, regenerated inventory, and `git diff --check` passed. No capability was promoted; exact/materialized 32-GiB, certified x86-64, production CVD/service, resource/fanotify, Sonic1, independent format-8, and final release qualification remain open. Receipt: `docs/largefile-task-receipts/R08-msxml-empty-child-maxfiles-2026-09-13.md`.

R08 current-source MSXML legacy self-closing empty-child MaxFiles accounting (2026-09-13 UTC): recognized self-closing MSXML Base64 and callback elements now use shared empty-child admission, preserving inclusive MaxFiles accounting and cache taint; current-source ARM64 Release and ASAN/UBSAN regressions pass 4/4 each, source guards, snapshot, inventory, and `git diff --check` pass, and no capability was promoted. Certified x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify, Sonic1, independent format-8, and final release qualification remain open. Receipt: `docs/largefile-task-receipts/R08-msxml-self-closing-empty-child-maxfiles-2026-09-13.md`.

R08 current-source XAR empty-subdocument MaxFiles accounting (2026-09-13 UTC): recognized XAR subdocuments now remain on the descriptor-admission path even when their XML body is empty or self-closing, preserving inclusive MaxFiles accounting and cache taint; the current-source ARM64 Release and ASAN/UBSAN `xar_subdoc` suites pass 2/2 each, source guards/snapshot/inventory/case-map/diff checks pass, no capability was promoted, and certified x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify, Sonic1, independent format-8, and final release qualification remain open. Receipt: `docs/largefile-task-receipts/R08-xar-empty-subdocument-maxfiles-2026-09-13.md`.

R08 current-source MIME empty-attachment export (2026-09-14 UTC): recognized MIME attachments with no body lines now produce a named zero-byte fileblob and remain eligible for the owning descriptor scan path, instead of being discarded before nested MaxFiles admission; with the checked-in test root certificate bound through `CVD_CERTS_DIR`, the current-source ARM64 Release and ASAN/UBSAN `cl_api` runs each execute 529 checks with zero failures, including the new regression, and the sanitizer run reports no diagnostic. Focused Release and ASAN/UBSAN mail controls also pass `mail` 16/16, `mail_api` 4/4, `mail_map` 2/2, `mail_partial` 1/1, and `mhtml` 5/5; the separate MHTML TCase now receives the explicit `T` timeout, and the ASAN/UBSAN run passes with only `T=1200`. Source guards/snapshot/inventory/case-map/diff checks pass. No capability was promoted; certified x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify, Sonic1, independent format-8, complete MIME corpus, and final release qualification remain open. Receipt: `docs/largefile-task-receipts/R08-mime-empty-attachment-admission-2026-09-14.md`.

R03 current-source bounded Release and ASAN/UBSAN matrix (2026-09-14 UTC): after rebuilding the complete current-source trees, the bounded CTest matrix excluding only the established ARM64 aggregate `libclamav` timeout passed 27/27 in Release and 27/27 under ASAN/UBSAN, including application, daemon, milter, Rust, freshclam, sigtool, ingress, protocol, resource, source-guard, acceptance-schema, case-map, and late-member controls. The sanitizer log contains no ASan/UBSan/LeakSanitizer/runtime diagnostic. No capability was promoted; certified x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify, independent format-8, Sonic1, complete parser-family evidence, and final release candidate review remain open. Receipt: `docs/largefile-task-receipts/R03-current-source-release-asan-matrix-2026-09-14.md`.

R08 current-source EGG parser revalidation (2026-09-14 UTC): current-source Release and ASAN/UBSAN EGG selectors each pass `egg_map` 16/16, `egg_metadata` 1/1, and `egg_sfx` 3/3 with zero failures or errors and no sanitizer diagnostics. The empty `egg` selector has zero registered tests and is not counted. No capability was promoted; complete EGG/SFX corpus, certified x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify, Sonic1, independent format-8, and final release evidence remain open. Receipt: `docs/largefile-task-receipts/R08-egg-current-source-revalidation-2026-09-14.md`.

R08 current-source Rust parser revalidation (2026-09-14 UTC): current-source Release and ASAN/UBSAN Rust selectors each pass `rust_lha` 10/10, `rust_alz` 3/3, `rust_onenote` 5/5, and `rust_map` 2/2 with zero failures or errors and no sanitizer diagnostics. The exact 32-GiB OneNote reader-boundary case remains covered; the attachment handoff regression is bounded just above the former 256-MiB whole-input parser ceiling to avoid synthetic-tail compatibility scanning. Source guards, snapshot, inventory, acceptance map/schema, and `git diff --check` pass. No capability was promoted; certified x86-64, exact/materialized 32-GiB attachment coverage, production CVD/service, resource/fanotify, Sonic1, independent format-8, complete parser-family corpus breadth, and final release evidence remain open. Receipt: `docs/largefile-task-receipts/R08-rust-current-source-revalidation-2026-09-14.md`.

R03 current-source Release and ASAN/UBSAN matrix refresh (2026-09-14 UTC): after reconfiguring both retained build trees so their CMake and build-manifest identities match the current source, the bounded CTest matrix excluding only the established aggregate ARM64 `libclamav` timeout passed 27/27 in Release in 128.81 seconds and 27/27 under ASAN/UBSAN in 502.89 seconds. The sanitizer log contains no ASan/UBSan/LeakSanitizer/runtime diagnostic. No capability was promoted; certified x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify, independent format-8, Sonic1, complete acceptance records, and final release review remain open. Receipt: `docs/largefile-task-receipts/R03-current-source-release-asan-matrix-rust-2026-09-14.md`.

R04/R10 current-source service acceptance parity (2026-09-14 UTC): current-source ARM64 Release and ASAN/UBSAN development service captures each wrote 36 independently schema-verified records covering six structured clamd report commands and six clamdscan modes across clean, detection, and limit outcomes. Each set has 12 `COMPLETE`, 12 `DETECTION_TERMINATED`, and 12 `LIMIT_INCOMPLETE` records, with exact identities, resource phases, health, cleanup, and lifecycle artifacts; the sanitizer capture has no diagnostics. No capability was promoted; exact/materialized 32-GiB, certified x86-64, production CVD, resource/fanotify, milter, Sonic1, independent format-8, and final release evidence remain open. Receipt: `docs/largefile-task-receipts/R04-R10-current-source-service-parity-2026-09-14.md`.

R02/R04 resource-phase budget binding (2026-09-14 UTC): the generic acceptance-record parser now validates measured `rss`, `pcre`, `post-pcre`, and `temporary` tokens against the reviewed 32-GiB overall, 40-GiB PCRE, strictly-below-12-GiB post-PCRE, and 64-GiB temporary budgets; runtime producers and fixtures now serialize the strict post-PCRE operator. New boundary tests and the existing resource/producer/schema/source-guard suites pass. No capability was promoted and no full-size or certified evidence was produced. Receipt: `docs/largefile-task-receipts/R02-R04-resource-phase-budget-binding-2026-09-14.md`.

R08 current-source PDF native-width LZW filter chain (2026-09-14 UTC): supported multi-filter PDF chains containing LZW no longer hit the stale top-level `UINT32_MAX`/allocation pre-admission checks; the reader-based LZW path now receives the same native-width bounded-chain admission as the other supported filters, while an LZW/FAX mixed chain preserves the legacy fail-visible boundary. The current-source ARM64 Release and ASan/UBSan `cl_api` runs each pass 529/529 with zero failures or errors, and the sanitizer log has no diagnostics. Source guards, snapshot, inventory, acceptance map/schema, and `git diff --check` remain required after the receipt/documentation update; no capability was promoted. Certified x86-64, exact/materialized multi-gigabyte PDF, production CVD/service, resource/fanotify, Sonic1, independent format-8, complete parser-family, and final release evidence remain open. Receipt: `docs/largefile-task-receipts/R08-pdf-native-width-lzw-chain-2026-09-14.md`.

R03 current-source application smoke (2026-09-14 UTC): the retained ARM64 Release `clamscan` loaded an independently generated temporary HDB, returned `OK` for `/src/README.md`, detected the exact generated 21-byte input with exit 1 and `LargeFile.Runtime.Smoke.UNOFFICIAL`, and emitted a matching structured `--report-json` record with `DETECTION_TERMINATED`, exact alert, and byte counters. Temporary smoke files were removed. This confirms basic current-binary clean/detection/report behavior but does not qualify a capability or release; certified x86-64, exact/materialized 32-GiB, sanitizer service parity, production CVD, resource/fanotify, Sonic1, complete case records, and final readiness remain open. Receipt: `docs/largefile-task-receipts/R03-current-source-application-smoke-2026-09-14.md`.

R03 current-source `ENABLE_WERROR` flag propagation (2026-09-14 UTC): both CMake warning-flag helpers now preserve prior accumulator contents, so an isolated `ENABLE_WERROR=ON` configuration reports `-Werror -Wall -Wextra -Wformat-security` in `WARNCFLAGS`; the focused `clamav` build fails on pre-existing bundled-regex signedness warnings, providing deterministic proof that Werror is active without claiming global warning-clean qualification or promoting the capability. Receipt: `docs/largefile-task-receipts/R03-werror-flag-propagation-2026-09-14.md`.

R03 current-source Werror warning cleanup (2026-09-14 UTC): regex, XZ/7-Zip, generated YARA, fileblob, AC/BM matcher, TFLite, and InstallShield warning sites were corrected and their focused objects/targets compile cleanly under effective Werror; the global library build now reaches the legacy NSIS bzip2 macro-driven fallthrough warnings, so warning-clean release qualification remains pending and the capability stays pending. Receipt: `docs/largefile-task-receipts/R03-werror-warning-cleanup-2026-09-14.md`.

R09 current-source required-unsupported revalidation (2026-09-14 UTC): the dedicated seven-capability R09 Check group passes 57/57 in both the current ARM64 Release and ASAN/UBSAN binaries, with no sanitizer diagnostic. The run is bound to source manifest `19330bf9d99e14ef53661bf531e3cb402200abe0e395dbb44b49af86356a7667` and the rebuilt test binaries; no capability was promoted because certified x86-64, full-size, independent corpus, production-CVD/service, and final evidence remain open. Receipt: `docs/largefile-task-receipts/R09-required-unsupported-revalidation-2026-09-14.md`.

R04 current-source `clamscan` file/stdin development acceptance (2026-09-14 UTC): the retained ARM64 Release and ASAN/UBSAN `clamscan` binaries each pass the existing development acceptance producer's six cases: clean, exact-marker detection, and MaxFileSize limit over both file and stdin ingress. Each capture writes six schema-validated records with source/build/oracle provenance; targeted log inspection finds no ASan/UBSan/LeakSanitizer/runtime diagnostic. Evidence is retained outside the source tree under `/private/tmp/clamav-r04-clamscan-development-20260914` and `/private/tmp/clamav-r04-clamscan-asan-development-20260914`; no capability was promoted because the fixtures are small ARM64 development inputs and do not establish certified x86-64, full-size, production-CVD, resource, service, or final release evidence. Receipt: `docs/largefile-task-receipts/R04-clamscan-file-stdin-development-2026-09-14.md`.

R03 current-source Werror application closure (2026-09-14 UTC): the complete current-source `ENABLE_WERROR=ON` build now passes all configured library and application targets, after portable fixes for legacy state-machine fall-through, signedness/width checks, pointer typing, allocation bounds, daemon portability, and clamsubmit MIME form handling. Rebuilt ARM64 Release and ASAN/UBSAN trees each pass `cl_api` 529/529 with zero failures or errors; the sanitizer run reports no diagnostic. This remains development evidence only: no capability was promoted, and certified x86-64, exact/materialized 32-GiB, production-CVD/service, resource/fanotify, Sonic1, independent format-8, complete acceptance records, and final release review remain open. Receipt: `docs/largefile-task-receipts/R03-werror-application-closure-2026-09-14.md`.

R04/R10 current-source service and CLI capture (2026-09-14 UTC): current-source ARM64 Release and ASAN/UBSAN development producers each wrote 36 schema-verified clamd/clamdscan records and 6 schema-verified clamscan file/stdin records, covering clean, exact detection, and MaxFileSize-limit outcomes. All records report health and cleanup pass; the sanitizer captures emit no diagnostics. This is development-only small-fixture evidence and does not promote capabilities or replace certified x86-64, exact/materialized 32-GiB, production-CVD, measured resource/fanotify, Sonic1, independent format-8, or final release evidence. Receipt: `docs/largefile-task-receipts/R04-R10-current-source-service-capture-2026-09-14.md`.

R03 current-source warning gate refresh (2026-09-14 UTC): the complete current-source `ENABLE_WERROR=ON` build passed with exit 0 across the configured library and application targets. Release `cl_api` passed 529/529; focused Release and ASAN/UBSAN 7-Zip, YARA, and regex suites passed with no sanitizer diagnostics. The current ASAN aggregate `cl_api` rerun did not return and is not counted as a pass. The maximal-warning exploration advanced through generated YARA and core utility layers before reaching broad legacy conversion diagnostics in `libclamav/str.c`. The current-source manifest is `b1955dbea032097610e1917cd70be7db4ffad87e20079d4ba7cc2d225f1a8bcc`. No capability was promoted; certified x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify, Sonic1, independent format-8, complete acceptance records, and final release review remain open. Receipt: `docs/largefile-task-receipts/R03-werror-application-closure-2026-09-14.md`.

R03 current-source warning gate revalidation (2026-09-14 UTC): after the
strict-cleanup edits, the complete current-source `ENABLE_WERROR=ON` build
still passed all configured library and application targets. The rebuilt
Release `cl_api` subset passed 529/529, and focused Release and ASAN/UBSAN
7-Zip, YARA, and regex cases passed with no sanitizer diagnostics. An
unfiltered Release `check_clamav` run exposed five HTML/MSXML MaxFiles
assertions in aggregate ordering; each of those five cases passes when
isolated, so that run is not counted as a clean aggregate. The ASAN aggregate
was not repeated after this rebuild because the prior bounded rerun did not
return. Maximal-warning exploration now passes `str.c`, `strlcat.c`, `table.c`,
`www.c`, `disasm.c`, and `filtering.c` before the larger legacy warning set in
`matcher-ac.c`. The current-source manifest is
`5b64f7a13b71b0320aa5104d9c8f9bbc1e941a30c99bb62a612686e0fc8f0fe4`. No
capability was promoted; certified x86-64, exact/materialized 32-GiB,
production CVD/service, resource/fanotify, Sonic1, independent format-8,
complete acceptance records, and final release review remain open. Receipt:
`docs/largefile-task-receipts/R03-werror-application-closure-2026-09-14.md`.

R03 current-source Release and ASAN/UBSAN strict-refresh (2026-09-14 UTC):
the complete Werror, Release, and ASAN/UBSAN application builds passed after
the strict-warning cleanup. Release `cl_api` passed 529/529, and focused
Release/ASAN/UBSAN 7-Zip, YARA, and regex cases passed without sanitizer
diagnostics. The bounded Release matrix completed 26/27 because the procfs
RSS sampler raced a short-lived process; its isolated retry passed, making all
27 bounded Release tests pass across the two runs. The ASAN/UBSAN matrix
reached `clamscan` (24/27) before the daemon test terminated the retained
container with exit 137; the remaining cases are not counted. An unfiltered
Release aggregate reached 2,942 checks with five HTML/MSXML MaxFiles failures
only in group ordering; all five cases pass in isolation. The current-source
manifest is `5b64f7a13b71b0320aa5104d9c8f9bbc1e941a30c99bb62a612686e0fc8f0fe4`.
No capability was promoted; certified x86-64, exact/materialized 32-GiB,
production CVD/service, resource/fanotify, Sonic1, independent format-8,
complete acceptance records, and final release review remain open. Receipt:
`docs/largefile-task-receipts/R03-current-source-release-asan-matrix-strict-refresh-2026-09-14.md`.

R03/R08 current-source HTML and MSXML MaxFiles revalidation
(2026-09-14 UTC): the remaining five Release aggregate failures were
reproduced as real issues rather than test-order artifacts. HTML normalization
now preserves nested non-success limit results such as `CL_EMAXFILES`, and
the four direct MSXML regressions now use a compiled engine, shared
configuration, and recursion layer. The final Release aggregate passes
2,942/2,942; direct Release and ASAN/UBSAN HTML and MSXML runs pass 14/14
each, the complete Werror build passes, and the ASAN/UBSAN runs emit no
sanitizer diagnostics. Source guards, snapshot, acceptance map/schema,
regenerated inventory, and `git diff --check` pass. The current-source
manifest is `ec37159c793ad0a9b41589a54baf4c8533ca95fd32935b5d79093bc7f955cbfb`.
The complete configured current-source Release CTest suite also passes 28/28
in 196.47 seconds.
No capability was promoted; certified x86-64, exact/materialized 32-GiB,
production CVD/service, resource/fanotify, Sonic1, independent format-8,
complete capability-specific records, and final release review remain open.
Receipt:
`docs/largefile-task-receipts/R03-R08-html-msxml-maxfiles-2026-09-14.md`.

R07 independent format-8 prerequisite re-audit (2026-09-14 UTC): Apple
Clang 21.0.0 is installed on the arm64 macOS host, but no `llvm-as`, `llc`,
or external `clambc` compiler is available on the host or in the retained
Docker image. Generic Clang output would not provide a ClamAV CBC format-8
artifact with the required v2 ABI metadata, so the external compiler/artifact
blocker remains precise and unchanged. No software was installed or
downloaded, and no capability was promoted. Receipt:
`docs/largefile-task-receipts/R07-format8-artifact-prerequisite-2026-09-12.md`.

R08/R03 current-source Sonic1 exact library edge (2026-09-16 UTC): the
current-source Linux x86-64 Release `largefile_library_exact_32g` test passed
1/1 in 341.08 seconds through path, descriptor, and fmap APIs, reaching the
exact marker at offset `34359738304` and binding the expected strong-indicator
verdict, `DETECTION_TERMINATED`, exact 32-GiB limits, and post-run cleanup.
This is a bounded library-ingress slice after the OneNote descriptor-retention
fix, not a fully materialized release-family or R11 vertical qualification;
no capability was promoted. Receipt:
`docs/largefile-task-receipts/R08-R03-sonic1-exact-library-32g-current-20260916.md`.

R11 current-source Sonic1 materialized ZIP late-member slice (2026-09-16
UTC): the Linux x86-64 Release `clamscan` clean control completed a
materialized 32-GiB stored ZIP in 330.262 seconds, and the matching isolated
signature control detected its late marker at outer-file offset
`34359738091` in 264.276 seconds with `DETECTION_TERMINATED`. The independent
oracle matched the exact fixture hash before and after both scans. A
cache-aware integrity control found one post-scan buffered-read byte differing
from direct I/O at offset `19155960935`; targeted cache eviction restored the
expected byte and the full oracle passed, but the origin remains unresolved.
An isolated daemon/client extension then detected the same marker through
`clamdscan` path and FD-passing ingress, with structured `DETECTION_TERMINATED`
reports carrying the exact root size and alert offset. The same service
profile's INSTREAM control returned structured `RESOURCE_FAILURE` because the
host's approximately 54 GiB free space could not satisfy the 40-GiB
exploratory temporary budget plus stream/extraction needs. The source checkout
was dirty and the build identity was older, so these daemon/client results are
exploratory controls only. No capability was promoted; R11 remains pending
unconditional integrity qualification, alongside complete production
CVD/service, sanitizer, resource, on-access, and final release evidence. Receipt:
`docs/largefile-task-receipts/R11-sonic1-materialized-zip-cache-aware-20260916.md`.

R11 normalized-mode parity and fixture-integrity follow-up (2026-09-16 UTC):
the daemon and direct `clamscan --normalize=yes` controls were repeated with
explicit 32-GiB `MaxHTMLNormalize`, `MaxHTMLNoTags`, `MaxScriptNormalize`,
and `MaxZipTypeRcg` settings. Both returned structured `UNSUPPORTED` results
with reason `ZIP member did not reach a complete extraction state`, but the
fixture had already shown one cache-resident prefix byte change and a second
`0x51` appeared during the independent prefix check. Targeted page eviction
restored both observed bytes to `0x50`; the corrected full oracle
revalidation then passed as tracked async job
`job_560045d795b74a838d87a3f13f5e5af3` with the expected fixture SHA-256,
exact size, and marker coordinates. These observations do not justify parser
or temporary-space changes and do not promote R11. Receipt:
`docs/largefile-task-receipts/R11-sonic1-materialized-zip-cache-aware-20260916.md`.

MCP-SSH asynchronous extension and post-scan integrity closure (2026-09-16
UTC): Sonic1's documented tracked async command path was confirmed with a
600-second effective timeout and typed `docker exec` arguments. The current
source `clamscan` clean run required the explicit `CVD_CERTS_DIR=/src/certs`
environment and completed in 325.239 seconds with exact 32-GiB/64-GiB/256-GiB
resource settings, three parser operations, and status `COMPLETE`. The
post-run oracle again found one cache-resident `0x51` byte at offset
`8827839591`; targeted `POSIX_FADV_DONTNEED` eviction restored `0x50` and the
full fixture hash returned to the expected value. The async mechanism is
usable, but Sonic1 fixture instability still prevents qualification promotion.
Receipt:
`docs/largefile-task-receipts/R11-sonic1-materialized-zip-cache-aware-20260916.md`.

R05 current-source Sonic1 sparse 32-GiB+1 service rerun (2026-09-16 UTC):
the documented MCP-SSH tracked foreground/async path ran the x86-64 `clamd`
with separate `AlertExceedsMax` on/off configurations. `FILDESREPORT` on
returned `DETECTION_TERMINATED` with the exact
`Heuristics.Limits.Exceeded.MaxFileSize` alert; off returned
`LIMIT_INCOMPLETE` with status 24. Both records independently verified exact
34,359,738,369-byte sparse metadata, zero parser/matcher/logical/temp work,
cleanup, and PONG health before and after. The combined evidence validator
passed, but the dirty source/build identity means this remains development
evidence and does not promote the release capability. Receipt:
`docs/largefile-task-receipts/R05-sonic1-oversize-admission-current-20260916.md`.

R13 Sonic1 fanotify capability preflight (2026-09-16 UTC): the documented
MCP-SSH tracked async path was used with a 600-second effective timeout. UID 0
inside the existing x86-64 development container still returned
`fanotify_init: Operation not permitted`. A disposable `docker run --rm
--privileged` probe with the current clamonacc binary, resolved build
libraries, and an explicit scoped config passed fanotify initialization and
then stopped at the expected missing clamd connection. This narrows the
environmental issue to ordinary-container capability: it does not provide
R13 permission allow/deny events, a private mount, or qualification evidence.
Temporary staged files and the disposable container were cleaned up; no
capability was promoted. Receipt:
`docs/largefile-task-receipts/R13-sonic1-fanotify-capability-preflight-2026-09-16.md`.

R13 Sonic1 real permission development smoke (2026-09-16 UTC): a disposable
privileged Linux x86-64 clamd/clamonacc pair exercised real unprivileged opens
through `OnAccessIncludePath`. Prevention mode allowed a clean open, denied a
signature detection with `EPERM`, and denied a two-byte fixture under a
one-byte on-access limit while logging status 24. Monitoring-only mode allowed
the signature fixture while logging `FOUND` and did not label it clean. The
full 64-GiB profile was separately rejected by the application admission gate
because Sonic1 had 57,154,293,760 free temp bytes versus the required
73,014,444,032; the smoke used 40 GiB only as an explicitly development-only
profile. Exact tracked jobs, container IDs, cleanup, and the absence of source
or production mutation are recorded, but no retained kernel-event artifacts,
full R13 matrix, sanitizer/resource proof, or qualification promotion exists.
Receipt: `docs/largefile-task-receipts/R13-sonic1-permission-smoke-2026-09-16.md`.

R13 real-event capture primitive (2026-09-16 UTC): added
`tools/largefile_fanotify_capture.py` and its focused tests. On an authorized
Linux root runner, the primitive requires an existing privately propagated
mount, creates a real `FAN_OPEN_PERM` fanotify group, records raw metadata and
case-bound event sequence IDs, explicitly answers its observer group, and
executes the fixture open through a non-root actor. It emits a JSONL kernel
event artifact and a bound actor-result artifact; it never fabricates scan
completion, clamonacc decisions, or kernel events. The R13 evidence verifier
now parses and validates those retained artifacts, including the permission
mask, raw metadata, selected event binding, actor UID, and observed allow/deny
action. Capture tests 6/6, fanotify evidence tests 10/10, source guards, and
`git diff --check` passed. No privileged runner artifact was produced in this
macOS turn, so R13 remains unqualified and the existing Sonic1 resource and
certified-runner blockers remain unchanged.

R13 Sonic1 capture-primitive smoke (2026-09-16 UTC): the corrected primitive
was staged through Docker provenance/exec and run in a disposable privileged
Linux x86-64 container. On the current source bind, observed as private ext4,
it marked `FAN_EVENT_ON_CHILD | FAN_OPEN_PERM`, captured one real permission
event with raw metadata matching the structured version/length/mask/FD/PID
fields, answered the observer group, and recorded a successful non-root UID
65534 actor open. The transient script and artifacts were removed successfully
and no clamd/clamonacc or qualification result was claimed. Local capture
tests passed 7/7, evidence tests passed 15/15, and the remote disposable run
exited 0. Receipt:
`docs/largefile-task-receipts/R13-sonic1-fanotify-capture-primitive-2026-09-16.md`.

R13 MCP-SSH async continuation (2026-09-16 UTC): reviewed the Sonic1
`sonic1-camera-key` policy and used the tracked `ssh_command_start` path with
the canonical current-source container. The preview admitted an effective
600-second async job; status polling reached a terminal failure without a
timeout or detached process. A bounded diagnostic identified the honest
cause as `committed inventory is stale` in the older remote source bind. The
async path is proven as transport orchestration only; no remote output was
promoted as source or qualification evidence. Receipt:
`docs/largefile-task-receipts/R13-sonic1-mcp-ssh-async-continuation-2026-09-16.md`.
The follow-up bounded inventory/provenance check confirmed the same container
(`clamav-current-source-20260915`) remains on commit
`08b3ab820e40ac8bd307b0c78c03c94884f1b` with unrelated dirty artifacts, while
the local checkout is at `6312634ec24539dc6087a76df401a81b8e9aca7c`; it was
left untouched.
The current checkout was also packaged as an 18,610,167-byte archive with
SHA-256 `0a8abc82f48325d96642b24f5f126c06f551e9ccda4c30ef70c8b8b4024de583`.
The documented durable upload attempt for a new `/tmp` destination was
rejected before transfer creation by the authoritative MCP-SSH policy reason
`file_write_limit_exceeded`; no remote file or existing transfer was changed.

R04/R13 case-contract hardening (2026-09-16 UTC): aligned the reviewed
`on-access:permission` map with R13's six required outcomes by adding
resource, timeout, and parser failure cases. The fanotify evidence verifier
now requires each prevention case to retain one case-bound structured
`on-access-scan` report with matching completion/exit fields, verdict/reason,
and non-negative scan counters; arbitrary text can no longer satisfy the
`scan-report` role. The map, verifier, and negative tampering tests passed
(`15/15` fanotify evidence tests, `15/15` acceptance-case tests), followed by
the full source-guard suite. This remains schema and verifier progress only;
no R13 qualification result was promoted.

R13 permission-decision and monitoring evidence binding (2026-09-16 UTC):
the fanotify verifier now distinguishes the capture primitive's explicit
observer `FAN_ALLOW` response from ClamAV's retained production permission
response, requiring the latter to match each case's declared `FAN_ALLOW` or
`FAN_DENY`. Monitoring-only cases now also carry a fixture digest and a
case-bound structured `on-access-scan` report instead of an arbitrary report
text file. Negative tests cover missing ClamAV responses and misbound
monitoring reports; the focused fanotify suite passes 17/17 and the
acceptance-case suite passes 15/15. No R13 qualification result was promoted.
Receipt: `docs/largefile-task-receipts/R13-fanotify-decision-binding-2026-09-16.md`.

R13 clamonacc report-to-permission event join (2026-09-16 UTC): the
application-side evidence sinks now assign one process-local event ID before
each fanotify permission scan. The validated terminating clamd report, or
one final fail-closed fallback after all retries, is published with that same
`clamonacc_event_id`; the fanotify JSONL record retains the actual kernel
response and event metadata under the same ID. This prevents stream order from
being used as proof and keeps transient retry failures from creating duplicate
reports for one permission event. The final fanotify verifier also requires
that ID on each prevention scan-report artifact. The new bounded case binder
joins the observer event, clamonacc permission JSONL, actor result, and raw
report, rejecting ambiguous metadata matches, failed response writes, and
stale/bound report identities before emitting verifier-shaped artifacts. The
disposable ARM64 Clang/CMake `clamonacc` target linked successfully; focused
capture/evidence/binder/acceptance tests (7/7, 18/18, 5/5, and 15/15), the
604-capability map, source guards, and diff checks passed. Release
readiness remains blocked with zero qualified capabilities because certified
Linux x86-64/full-size evidence and the Sonic1 source/space prerequisites are
still absent. Receipt:
`docs/largefile-task-receipts/R13-clamonacc-evidence-sinks-2026-09-16.md`.

R13 independent-verifier invariant hardening (2026-09-16 UTC): the kernel
artifact verifier now requires exactly one target-bound event per retained
JSONL artifact, and the actor verifier binds exit status to the observed open
result. Negative regression coverage was added for both contradictions. The
focused evidence suite passes 20/20; no qualification result was promoted.

R13 MCP-SSH policy recheck (2026-09-16 UTC): a fresh Sonic1
`ssh_command_preview` admitted `operation="start"` with an effective timeout
of 3600 seconds, extending the earlier 600-second observation. A tracked
server-side clone job reached exit 128 because the private GitHub remote
requested credentials; the documented client-local durable upload handoff was
also denied with `file_write_limit_exceeded`. No remote source was promoted,
and the existing stale container was left untouched.

R13 clamonacc retry report publication (2026-09-16 UTC): each scan attempt's
structured report is now buffered in a temporary stream, discarded when a
retry is superseded, and published only once after the final attempt. If no
terminating report is retained, one fail-closed fallback is emitted. This
removes duplicate JSONL records for a single on-access event; source guards and
diff checks pass. Runtime qualification remains pending.

R03 Sonic1 capacity recheck (2026-09-16 UTC): the documented tracked
MCP-SSH asynchronous path was freshly verified on Linux 5.15 x86-64. Sonic1
reported 63,953,227,776 available memory bytes, above the roadmap's 48-GiB
headroom minimum, but only 57,167,429,632 bytes available on disk-backed
`/tmp`, below the 68-GiB temporary-space prerequisite. The runner therefore
remains blocked for full-size qualification on temporary capacity; no source,
container, or qualification evidence was changed. Receipt:
`docs/largefile-task-receipts/R03-sonic1-capacity-recheck-2026-09-16.md`.
The accompanying read-only `/tmp` inventory found approximately 34.36 GB in
`clamav-materialized-edge-20260909` and 34.90 GB in the known stale
`clamav-32gb-current-20260915` source tree. These remain untouched pending an
explicit cleanup decision because they may contain retained evidence.

Local regression sweep after the R13 retry-report correction (2026-09-16
UTC): the complete Python tools discovery passed 199 tests with two
Linux-only filesystem controls skipped on macOS; the OneNote Cargo package
passed 80 unit and 5 integration tests; the source snapshot freshness check
and `git diff --check` also passed. This strengthens development verification
only; the modified C target and full-size release qualification remain
pending the current-source Linux runner.

R03 local container configure probe (2026-09-16 UTC): the existing
`clamav-largefile-local-toolchain2:latest` ARM64 image was used with the
current source mounted read-only and an out-of-tree build directory. CMake,
Clang, and Rust were available, but configuration stopped first on missing
Libcheck development files and, with tests disabled for diagnosis, on missing
JSONC development files. No software was installed and no qualification
claim was made. Receipt:
`docs/largefile-task-receipts/R03-local-container-configure-2026-09-16.md`.

MCP-SSH continuation lifecycle recheck (2026-09-16 UTC): Sonic1 admitted a
60-second tracked `ssh_command_start`; a 25-second job remained observable as
running beyond the synchronous window and then completed with exit 0. Bounded
output retrieval reached EOF, and the probe made no remote source, Docker, or
filesystem changes. Receipt:
`docs/largefile-task-receipts/R13-sonic1-mcp-ssh-async-continuation-2026-09-16.md`.

R03 local application-target probe (2026-09-17 UTC): the existing ARM64
`clamav-largefile-local-toolchain2:latest` image was reused without installing
software. Its cached library-only configuration was reconfigured against the
current source successfully, but enabling application targets stopped at the
missing curl development header/library pair. A temporary type-only curl stub
did not produce a build claim; preprocessing also exposed incomplete OpenSSL
development headers in the image. The existing container was stopped after
the probe. Certified current-source application compilation remains pending
an authorized image/runner with the required development dependencies and
Sonic1 remains below the disk-backed temporary-space prerequisite. Receipt:
`docs/largefile-task-receipts/R03-local-app-target-probe-2026-09-17.md`.

R03 Sonic1 existing x86-64 build environment (2026-09-17 UTC): the known
container was inspected read-only and confirmed to contain curl/OpenSSL
development headers, `ENABLE_LIBCLAMAV_ONLY=OFF`, `ENABLE_CLAMONACC=ON`, and
an existing `clamonacc` target/artifact. Its `/src` bind remains commit
`08b3ab8…`, not the current checkout's `6312634…`, so the executable and object
were not used as evidence. Current-source delivery and Sonic1 temporary-space
admission remain the external prerequisites. Receipt:
`docs/largefile-task-receipts/R03-sonic1-existing-x86-build-2026-09-17.md`.

R13 Sonic1 MCP-SSH async-limit recheck (2026-09-17 UTC): the current
`sonic1-camera-key` policy admitted a tracked `ssh_command_start` request for
86400 seconds only by returning the effective 3600-second limit. A live
tracked 25-second job remained observable past the synchronous request window,
then reached `state=succeeded` with exit 0; bounded output retrieval reached
EOF. The documented path therefore extends short synchronous commands but
does not authorize a single phase past one hour. Longer phases must be split
into tracked bounded jobs. No remote source, container, filesystem, or
qualification evidence changed. Receipt:
`docs/largefile-task-receipts/R13-sonic1-mcp-ssh-async-limit-2026-09-17.md`.

R13 clamonacc evidence-option documentation closure (2026-09-17 UTC): the
installed `clamonacc` man-page template now documents `--report-json=FILE`
and `--fanotify-evidence=FILE`, including their append-only JSONL behavior,
terminating-report/fail-closed fallback semantics, and the fact that evidence
capture does not alter the configured on-access policy. This aligns the
installed interface documentation with the already exposed help/options and
the R13 evidence contract. No runtime or qualification claim was promoted.
Receipt: `docs/largefile-task-receipts/R13-clamonacc-evidence-docs-2026-09-17.md`.

R06 OneNote spool pathname-replacement hardening (2026-09-17 UTC): the
streaming reader now keeps the securely-created owner file open for all spool
writes, while reopening independent reader handles only after validating their
Unix device/inode identity against that owner. This preserves independent
read offsets without introducing a close-and-reopen write window. A regression
replacing the spool pathname with a symlink is rejected, and the current
OneNote parser suite passes 81 unit tests plus 5 integration tests. The
configured Rust toolchain lacks `rustfmt`, so formatting was checked manually;
no formatter component was installed. Full-size/materialized and certified
x86-64 qualification remain open. Receipt:
`docs/largefile-task-receipts/R06-onenote-spool-path-hardening-2026-09-17.md`.

R07 format-8 artifact and MCP-SSH continuation recheck (2026-09-17 UTC): the
current checkout still contains no independent compiler-produced format-8
bytecode artifact; the retained bytecode directory contains only legacy/
format-7 controls and the historical `bytecode.cvd`. On Sonic1, a requested
86,400-second tracked start was admitted but clamped to the effective 3,600-
second policy limit, confirming that longer work must be split into bounded,
checkpointed jobs. Two identical read-only compiler searches then timed out
during SSH connect before any remote process started, so no remote artifact or
qualification result was inferred. R07 remains blocked by the missing
compatible compiler/fixture and current-source runner. Receipt:
`docs/largefile-task-receipts/R07-format8-artifact-prerequisite-2026-09-12.md`.

R03 Sonic1 async capacity recheck (2026-09-17 UTC): the documented
MCP-SSH `ssh_command_preview` → `ssh_command_start` path admitted a tracked
3,600-second async job, and status/output polling completed successfully.
The read-only `df -B1 -P` result found 57,165,213,696 bytes available on the
root filesystem and Docker overlays, and 33,400,041,472 bytes on `/dev/shm`;
no mount reaches the roadmap's approximately 68-GiB staging prerequisite.
The synchronous SSH timeout is therefore not the blocker, but current-source
Sonic1 qualification remains blocked by capacity plus the existing authorized
source-transfer/provenance boundary. Receipt:
`docs/largefile-task-receipts/R03-local-toolchain-recheck-2026-09-17.md`.

R03 Sonic1 source-tree inventory (2026-09-17 UTC): a tracked read-only
`find` scan located many historical ClamAV build/evidence directories but only
one `.git` directory, under `/tmp/clamav-32gb-current-20260915`. Read-only
`git -C` probes of that tree exited 128 without usable output; no alternate
current-source repository is available to replace the stale/dirty source
mount. Historical build directories remain unsuitable as current-source
provenance. Receipt:
`docs/largefile-task-receipts/R03-local-toolchain-recheck-2026-09-17.md`.

R03 Sonic1 provenance and capacity recheck (2026-09-17 UTC): the authorized
`sonic1-camera-key` container provenance still identifies container
`53f6ca8d4a29…`, image `sha256:c0c10e2d…`, and a writable `/src` bind sourced
from `/tmp/clamav-32gb-current-20260915`. Read-only checks report source
commit `08b3ab8…` with unrelated dirty artifacts, not the current checkout
`6312634…`; the container overlay has 55,825,768 KiB available, below the
73,014,444,032-byte roadmap temporary-space requirement. No remote mutation or
qualification evidence was performed. Receipt:
`docs/largefile-task-receipts/R03-sonic1-provenance-capacity-2026-09-17.md`.

R06 local Rust integration compile recheck (2026-09-17 UTC):
`cargo test -p clamav_rust --no-run` reached `openssl-sys v0.9.117` and
stopped because the macOS worktree has neither a discoverable OpenSSL
development installation nor `pkg-config`. The OneNote parser package itself
remains verified by 81 unit tests and 5 integration tests; no dependency or
Rust component was installed. This is an environment blocker for the full
Rust integration compile, not a parser test failure. Receipt:
`docs/largefile-task-receipts/R06-onenote-spool-path-hardening-2026-09-17.md`.

R02 resource-policy regression revalidation (2026-09-17 UTC): the independent
PCRE phase evidence suite passed 11 tests, the acceptance resource-contract
suite passed 7 tests, and the runtime and service evidence verifier regression
scripts both exited 0. The 32 GiB overall subcase remains explicitly distinct
from the 40 GiB PCRE ceiling and strict 12 GiB post-PCRE contract. No live
phase measurement or capability promotion was performed. Receipt:
`docs/largefile-task-receipts/R02-resource-policy.md`.

R08 LHA/LZH parser revalidation (2026-09-17 UTC): the vendored `delharc`
package passed 13 unit tests, including LHA v1/v2 decoding and cumulative
header-allocation rejection, plus one doctest. This isolated parser evidence
does not replace the unavailable top-level Rust integration build or certified
Linux x86-64/full-size capability evidence. Receipt:
`docs/largefile-task-receipts/R08-lha-delharc-revalidation-2026-09-17.md`.

R03 existing-container Rust integration probe (2026-09-17 UTC): the
pre-existing `rust:1.97-bookworm` image exposes OpenSSL 3.0.20 and libcurl
7.88.1, but an offline current-source `cargo test -p clamav_rust --no-run`
stopped before compilation because the pinned Git dependency `clam-sigutil`
is absent from the image's Cargo cache. No network fetch or installation was
performed. Receipt:
`docs/largefile-task-receipts/R03-local-app-target-probe-2026-09-17.md`.

R05 fixture/oracle revalidation (2026-09-17 UTC): the streaming ZIP late-member
suite passed 8 tests, the sparse-boundary corpus checker passed 5 tests, and
the service oversize evidence suite passed 23 tests. These controls validate
deterministic fixture/oracle construction and fail-closed evidence handling;
no full-size scanner run or capability promotion was performed. Receipt:
`docs/largefile-task-receipts/R05-streaming-zip-fixture-2026-09-13.md`.

R06 OneNote spool cleanup hardening (2026-09-17 UTC): Unix spool cleanup now
checks the owner file's device/inode before unlinking a replaced pathname, so
an unrelated regular file is not removed during parser drop. The symlink and
regular-file replacement regressions pass; the OneNote parser suite passes 82
unit tests and 5 integration tests. Receipt:
`docs/largefile-task-receipts/R06-onenote-spool-path-hardening-2026-09-17.md`.

R08 shared Rust temporary-spool ownership hardening (2026-09-17 UTC): the
common `TempSpool` used by ALZ, LHA/LZH, and OneNote now captures the Unix
device/inode of its opened descriptor and rechecks pathname identity before
cleanup unlink. Descriptor-identity failure is fail-closed and releases the
temporary reservation. Inventory parity, diff checks, and the complete source
guard suite passed. The top-level Rust integration compile remains blocked by
the local OpenSSL/`pkg-config` environment and the offline container's missing
`clam-sigutil` cache entry; no qualification claim was promoted. Receipt:
`docs/largefile-task-receipts/R08-rust-temp-spool-ownership-2026-09-17.md`.

R13 clamonacc report JSON publication boundary (2026-09-17 UTC): the
`--report-json` enrichment helper now validates the complete payload through
the shared strict JSON-object parser before adding the process-local event ID,
so trailing bytes, duplicate top-level keys, and non-object payloads cannot be
rewritten into evidence. It also rejects lengths above `UINT32_MAX` before the
shared API cast and cleans up the strict-parser temporary on every exit path.
The public client header now directly includes the stdio declaration required
by its `FILE *` interfaces. Inventory parity, diff checks, and the complete
source guard suite passed; current-source C runtime verification remains open
because the host lacks its generated build metadata/dependencies and the
authorized Sonic1 source transfer was denied by MCP-SSH policy. Receipt:
`docs/largefile-task-receipts/R13-clamonacc-report-json-boundary-2026-09-17.md`.

R13 fanotify evidence pathname JSON hardening (2026-09-17 UTC): the native
`--fanotify-evidence` serializer now validates multi-byte pathname sequences,
preserves valid UTF-8, and escapes malformed POSIX pathname bytes as JSON
Unicode escapes. A follow-up found and fixed the four-byte UTF-8 boundary
case; the exact helper-and-writer regression now covers valid three-/four-byte
output preservation, overlong encodings, surrogates, out-of-range values, and
truncation.
Inventory parity, diff checks, snapshot freshness, the focused helper
regression, and the complete source guard suite passed; current-source compile
and privileged fanotify runtime qualification remain open. Receipt:
`docs/largefile-task-receipts/R13-fanotify-json-utf8-2026-09-17.md`.

R09 Python compiled-bytecode skipped-read hardening (2026-09-17 UTC): the
bounded marshal walker now reads skipped payload ranges through 4-KiB fmap
windows instead of advancing over them without touching the backing source.
An in-range failure inside a large `co_code` payload is therefore preserved as
`CL_EREAD`, marked incomplete, and kept non-cacheable. A current-source C
regression constructs a valid legacy code-object envelope with a 300,000-byte
skipped payload and fails the fmap after the first 256 KiB; the case is
registered in both ordinary and required-unsupported suites. Inventory parity,
diff checks, and the complete source guard suite passed (604 capabilities).
The new linked C regression remains unexecuted because the local application
build lacks JSON-C/Check/curl development metadata and current-source Sonic1
delivery remains blocked. Receipt:
`docs/largefile-task-receipts/R09-python-skipped-read-2026-09-17.md`.

R09 AI-model skipped-read hardening (2026-09-17 UTC): the AI-model structural
walker now reads skipped ONNX/GGUF payload ranges through 4-KiB fmap windows
instead of advancing over them without touching the backing source. An
in-range failure inside a large ONNX producer metadata or GGUF string payload
is therefore preserved as `CL_EREAD`, marked incomplete, and kept
non-cacheable. Current-source C regressions construct valid ONNX and GGUF
structures with 300,000-byte skipped payloads and fail the fmap after the first
256 KiB; both cases are registered in ordinary and required-unsupported
suites.
Inventory parity, diff checks, and the complete source guard suite passed (604
capabilities). The new linked C regression remains unexecuted because the
local application build lacks JSON-C/Check/curl development metadata and
current-source Sonic1 delivery remains blocked. Receipt:
`docs/largefile-task-receipts/R09-ai-model-skipped-read-2026-09-17.md`.

R03 local toolchain image recheck (2026-09-17 UTC): both preinstalled ClamAV
toolchain images were inspected read-only with the current checkout mounted
read-only. They expose CMake and a C compiler plus OpenSSL headers, but no
JSON-C or curl development metadata/headers and no prebuilt `clamscan` or
`check_clamav` artifact. No dependency was installed or disabled, and no build
claim was made. Receipt:
`docs/largefile-task-receipts/R03-local-toolchain-recheck-2026-09-17.md`.

R08 Rust temporary-spool pathname inspection hardening (2026-09-17 UTC):
unexpected Unix `lstat()` failures during temporary-spool cleanup are now
fail-visible as `CL_EUNLINK`; missing paths and replaced identities remain
non-destructive. Added an `ENAMETOOLONG` regression alongside the existing
replacement-path control. Inventory parity, diff checks, and the complete
source guard suite passed (604 capabilities). The focused Rust test could not
link on the host because OpenSSL development discovery is unavailable; a
container retry compiled the crate but could not link its standalone test
binary without the production ClamAV C ABI symbols. MCP-SSH documentation was
also verified: `ssh.command.start` allows an effective 3600-second async
window, with explicit status/output polling; the available Sonic1 container
is stale relative to the current checkout, so no runtime qualification claim
was made. Receipt:
`docs/largefile-task-receipts/R08-rust-temp-spool-lstat-cleanup-2026-09-17.md`.

R06 OneNote parser cleanup propagation (2026-09-17 UTC): the parser's
`BlobSpoolBudget` now reports unexpected spool pathname/removal failures to the
scanner integration, which marks the containing scan incomplete while keeping
missing and replaced paths non-destructive. Unix reader reopening now uses
`O_NOFOLLOW|O_NONBLOCK`, preventing replaced symlinks from being followed and
replaced FIFOs from blocking before identity rejection. The new symlink-open,
replaced-FIFO, replaced-file, and overlong-path regressions and the full parser
suite passed: 84 unit tests and 5 integration tests.
Inventory parity, diff checks, and the complete source guard suite passed (604
capabilities). The production-linked C/Rust integration build and certified
runtime evidence remain open because the local host lacks OpenSSL/JSON-C/curl
development metadata and Sonic1 does not yet hold the current source. Receipt:
`docs/largefile-task-receipts/R06-onenote-spool-path-hardening-2026-09-17.md`.

R10 milter `SkipAuthenticated` file-list hardening (2026-09-17 UTC):
file-backed authenticated-user lists now accept empty/comment-only files with
the bypass disabled instead of writing at `regex[-1]`; long entries allocate
from their encoded regex expansion with `size_t` overflow checks, and final
terminator growth preserves allocation failures. The registered
`largefile_milter_skipauth` regression covers empty, comment-only, and 2047-byte
expanded entries, plus a one-character final allow-list entry without a
newline, and malformed allow-list cleanup. Both production and test translation units pass strict local
syntax checks, and the complete source guard suite passes with 604 capabilities.
The standalone runner compiles the exact production `allow_list.c` with only
the unavailable full regex/logging link layer stubbed and passes the focused
test both normally and under ASan/UBSan.
The linked CTest remains unexecuted because the preinstalled container lacks
Cargo 1.97+, so CMake configuration stops before compilation; no software was
installed and no capability was promoted. Full milter-linked, sanitizer,
resource-policy, Sonic1, service, and certified Linux x86-64 evidence remain
open. Receipt:
`docs/largefile-task-receipts/R10-milter-skipauth-empty-list-2026-09-17.md`.

R11 clamd legacy `writen()` zero-progress hardening (2026-09-17 UTC):
the daemon-local write-all helper now returns `-1` with `EIO` when a
non-zero request receives `write() == 0`, preventing an infinite loop on a
stalled descriptor. A focused production-linked `check_clamd_writen` target
and Linux write-fault injection cover the normal and zero-progress paths.
The source guard is registered; full CTest, sanitizer, current-source Sonic1,
and certified Linux qualification remain pending because the configured local
build prerequisites and current-source remote staging are still unavailable.
Receipt:
`docs/largefile-task-receipts/R11-clamd-writen-zero-progress-2026-09-17.md`.
stalled descriptor. A focused production-linked `check_clamd_writen` target
and Linux write-fault injection cover the normal and zero-progress paths.
The source guard is registered; full CTest, sanitizer, current-source Sonic1,
and certified Linux qualification remain pending because the configured local
build prerequisites and current-source remote staging are still unavailable.
Receipt:
`docs/largefile-task-receipts/R11-clamd-writen-zero-progress-2026-09-17.md`.

R11 follow-up: `fds_add()` now marks a newly allocated slot inactive before buffer initialization and decrements `nfds` when that initialization fails. The focused target injects command-buffer allocation failure and verifies no live descriptor remains.

R12 clamd poll-array and passed-descriptor lifecycle hardening (2026-09-17 UTC):
`realloc_polldata()` now checks its byte product and allocates replacement
storage before releasing the old poll array, preserving a valid cleanup path
when a resize allocation fails. `fds_cleanup()` and `fds_free()` now close
unclaimed ancillary descriptors held in `recvfd`. The focused production-linked
`check_clamd_writen` target injects a poll-array resize failure, verifies the
old array remains usable for teardown, and verifies an unclaimed passed
descriptor is closed on both removal cleanup and daemon-wide teardown.
Inventory parity, the snapshot check, `git diff --check`,
and the complete source guard suite passed (604 capabilities). Linked CTest,
sanitizer, current-source Sonic1, and certified Linux qualification remain
pending because the local dependency prerequisites and current-source remote
staging are unavailable. Receipt:
`docs/largefile-task-receipts/R12-clamd-fd-lifecycle-2026-09-17.md`.

R14 HFS+ inline extent terminator handling (2026-09-17 UTC):
`hfsplus_resolve_fork_block()` now accepts the normal all-zero terminator after
any number of inline extent descriptors, rejects half-empty and
post-terminator descriptors, and reaches the bounded ExtentOverflow lookup for
logical blocks beyond the inline list. The existing focused HFS+ overflow
fixture now uses one inline data/resource extent followed by the terminator,
then resolves the next block through the matching overflow records. Source
guards, inventory parity, the snapshot check, and `git diff --check` remain
required evidence; linked CTest, sanitizer, current-source Sonic1, and
certified Linux qualification remain pending because the local dependency
prerequisites and current-source remote staging are unavailable. Receipt:
`docs/largefile-task-receipts/R14-hfsplus-inline-extent-terminator-2026-09-17.md`.

R08 UDF Extended File Entry admission (2026-09-17 UTC): the anchored UDF ICB
walker now accepts bounded Extended File Entry descriptors (tag 266), checks
their fixed/extended-attribute/allocation descriptor size arithmetic, and
routes their regular-file metadata through the existing validated extent and
nested-scan path. The standards-shaped fixture now detects the nested marker
through an EFE child and rejects an EFE larger than its logical block with
sticky incomplete/cache-taint. The legacy linear descriptor walk remains an
explicit unsupported boundary, so the implementation is scoped to anchored
tree traversal. The full source-guard suite, inventory parity, snapshot check,
and diff checks passed; linked CTest, sanitizer, current-source Sonic1, and
certified Linux qualification remain pending because the local dependencies,
Docker runtime, and current-source remote connection are unavailable. Receipt:
`docs/largefile-task-receipts/R08-udf-extended-file-entry-2026-09-17.md`.

R08 UDF EFE follow-up (2026-09-17 UTC): the legacy linear UDF path now accepts
tag-266 Extended File Entry records, uses checked EFE sizing during descriptor
collection and extraction, and shares the existing allocation/empty-file
admission semantics. The compact legacy regression complements the anchored
valid and oversized-EFE cases. This removes the former explicit linear-path
unsupported boundary while leaving the existing allocation-form, logical-block,
corpus, sanitizer, Sonic1, and release qualification limits intact.

R08 UDF empty-directory MaxFiles admission (2026-09-17 UTC): the anchored UDF
directory walker now routes a recognized zero-length directory through the
shared empty-entry admission path, so an empty nested subtree consumes the
inclusive MaxFiles budget instead of returning clean without accounting. The
current standards-shaped corpus regression requires CL_EMAXFILES, the exact
Heuristics.Limits.Exceeded.MaxFiles reason, sticky incomplete state, and map
cache taint when the enclosing layer is already at its child limit. Source and
focused regression changes are recorded in
`docs/largefile-task-receipts/R08-udf-empty-directory-maxfiles-2026-09-17.md`;
linked CTest, sanitizer, Sonic1, and certified Linux qualification remain
pending because the local dependency/runtime and current-source remote
prerequisites are unavailable.

R13 clamonacc detection-report admission (2026-09-17 UTC): the on-access
structured report boundary now applies semantic status validation and requires
an exact non-empty alert name for infected frames before retaining or
publishing JSONL. This aligns the clamonacc socket path with the daemon report
consumer and prevents alert-less detections from being recorded as
authoritative evidence. The source guard and inventory checks were updated;
linked clamonacc runtime, sanitizer, Sonic1, and certified Linux fanotify
qualification remain pending because the local dependency/runtime and current
source remote prerequisites are unavailable. Receipt:
`docs/largefile-task-receipts/R13-clamonacc-report-json-boundary-2026-09-17.md`.

R13 Sonic1 transport diagnostic (2026-09-17 UTC): the documented
side-effect-free MCP-SSH connection check passed policy and address
resolution, then timed out during the fixed 20-second TCP-connect phase.
Authentication and SFTP were not reached, and `remote_started=false`. The
tracked async path remains usable only when the host is reachable; no async
timeout or remote mutation occurred in this recheck. Receipt:
`docs/largefile-task-receipts/R13-sonic1-mcp-ssh-async-limit-2026-09-17.md`.

R13 clamonacc unknown-size stream deadline (2026-09-17 UTC): unknown-size
on-access stream inputs now use one absolute `OnAccessCurlTimeout` source-read
deadline, including the final one-byte overflow probe. Idle open pipes fail
with `CL_ETIMEOUT`, EOF remains normal, and exact-ceiling overflow remains
`CL_EMAXSIZE`; continuous input cannot extend the deadline, and zero retains
the existing immediate-poll behavior. The exact production helper regression
passed for zero-timeout polling, idle timeout, EOF, and data readiness,
steady-input deadline behavior, and is registered as the Unix CTest
`largefile_clamonacc_stream_deadline` control. The full source-guard suite and
inventory parity then passed. This is
bounded implementation evidence only; linked clamonacc, sanitizer, certified
Linux, fanotify permission, production-database, and Sonic1 qualification
remain pending. Receipt:
`docs/largefile-task-receipts/R13-clamonacc-unknown-stream-deadline-2026-09-17.md`.

R02/R04 typed structured-report log format (2026-09-19): `kind=report`
workloads now validate the exact alert and native-width offset from their
independently checked JSON report, while accepting a frontend summary that
prints only `target: FOUND`. The typed path still requires a complete outcome
line and rejects unrelated or contradictory text; CLI, service, and legacy
workloads retain exact console-signature and offset validation. The acceptance
producer, post-run verifier, focused regressions, service-evidence regression,
604-row source guards, snapshot freshness, and diff checks passed. No
capability was promoted; certified current-source Linux/client output and
full-size qualification remain open. Receipt:
`docs/largefile-task-receipts/R02-report-log-format-2026-09-19.md`.

R02 typed-report outcome-line follow-up (2026-09-19): the structured-report
log validator now requires `target: OK` for clean reports and
`target: INCOMPLETE ...` for incomplete reports; only detection reports may
use the frontend's bare `target: FOUND` summary because their exact alert and
offset are bound by the JSON report. The service evidence fixture, focused
regressions, full source guards, snapshot freshness, and diff checks passed.

R02 direct-report budget parity (2026-09-19): the independent clamd
structured-report protocol verifier now requires `max_scan_size` to equal the
certified 64-GiB logical budget and rejects reports whose `logical_bytes`
exceed it. The FILDESREPORT wire fixture was brought up to the same contract,
and focused wrong-budget/over-budget regressions pass. No capability was
promoted; current-source certified Linux service evidence and final
qualification remain open.
