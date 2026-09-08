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
   and fuzzy-image work. R06 is blocked by the pinned parser's missing
   reader-backed API; its dependency audit is recorded in
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
