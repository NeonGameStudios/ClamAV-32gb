# Large-file roadmap task ledger

Task ID: `R00` with the first bounded `R01` provenance slice

State: `development-verified` for the R00/R01/R02/R03/R04 specification and
development slices; certified release remains blocked.

## Starting identity

- Canonical source: `/Volumes/512gbNVME/github-external/ClamAV-32gb`
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
| 423 `library:*` except `path`, `fd`, and `fmap` | `R08-LIBRARY` | Reader/parser/library call paths and fail-closed behavior |
| 17 `matcher:*` | `R08-MATCHER` / `R09-REQUIRED-UNSUPPORTED` slice | Native matchers, bytecode, YARA, PCRE, fuzzy-image |
| 41 `feature:*` | `R08-FEATURE` | Build switches, optional feature behavior, and capability output |
| 80 `parser:*` | `R08-PARSER` / `R09-REQUIRED-UNSUPPORTED` slice | Every scanner dispatch branch and parser-specific cases |
| 19 ingress rows (`clamd`, `clamdscan`, `clamscan`, `milter`, `on-access`) | `R10-INGRESS` | Front-end parity, reports, queueing, cleanup, and on-access semantics |
| 3 `library:*` ingress rows (`path`, `fd`, `fmap`) | `R10-INGRESS` | Modern library ingress parity |
| 14 `unsupported:*` | `R09-ALLOWLIST-AUDIT` | Verify deliberate first-release exclusions remain precise |

The counts above cover all 597 manifest rows. The recorded pre-R09 status was 0
qualified, 143 bounded, 433 pending, and 21 unsupported. The current manifest
keeps all seven required rows in scope as pending: 0 qualified, 143 bounded,
440 pending, and 14 allowlisted unsupported. Status labels do not qualify any
row.

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

R04 now maps all 597 capabilities to named required cases and validates the
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

The requested MCP-SSH Sonic3 runner was rechecked with the supplied
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
`docs/largefile-task-receipts/R03-r10-mcp-ssh-and-ctest-2026-09-09.md`.

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
