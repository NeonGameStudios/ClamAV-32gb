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
compiled-bytecode walker now models Python 3.11+ code objects with five leading
integers and eight object fields, followed by the first-line, line-table, and
exception-table objects. This corrects the earlier six-leading/nine-object
interpretation and keeps the modern fixture aligned with CPython's removal of
`co_nlocals` from the marshalled sequence. Source/evidence controls passed;
direct C execution, independent format-8 evidence, certified builds, and
production qualification remain open. Receipt:
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
