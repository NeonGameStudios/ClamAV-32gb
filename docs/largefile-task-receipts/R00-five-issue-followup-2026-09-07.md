# Task receipt: five-issue roadmap follow-up

Task ID / parent milestone: `R00` follow-up across `R03`, `R04`, `R06`,
`R09`, and `R10`

Scope: continue the five issues identified by the roadmap review using only
the canonical local checkout and existing disposable Docker artifacts. This
receipt records the current disposition; it does not promote any capability
to release-qualified.

Canonical source and branch:

- `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- `largefile-roadmap-qualification`
- working tree intentionally remains dirty and was not reset or cleaned
- pre-receipt source-manifest SHA-256:
  `7542de5ed0eb41d23d7253585be8822b39523e4e7354b9d1d26bf453387febb7`

## Issue disposition

1. **Certified qualification runner.** No Linux x86-64 runner was available
   locally, and no remote/MCP execution was used. The current ARM64 Docker
   build remains development evidence only. This issue is blocked by the
   external runner prerequisite.

2. **Safe refusal versus required implementation.** R09's five focused
   parser cases are fail-visible and raw matching remains available where
   required. Modern OneNote remains explicitly bounded at the dependency's
   whole-input API boundary; the pinned parser exposes only
   `parse_section_buffer(&[u8])` for the needed path, so no unsafe cap increase
   or whole-file adapter was added. R06 remains blocked by the dependency API.

3. **Capability-specific acceptance evidence.** The reviewed capability map,
   case suffix contracts, producer, and evidence-root hash checks are present
   and were rerun below. Standalone parser/matcher records now must retain an
   artifact whose digest is the scanned fixture digest; service records may
   instead bind that digest through the independently captured service-input
   identity. The current empty authoritative records state still blocks
   qualification; focused development records do not qualify unrelated
   capabilities.

4. **Service fixture binding.** The exact 32-GiB edge-size rule, allocation
   and `SEEK_HOLE` checks, mutation identity checks, and before/after evidence
   comparison are present. Their focused controls pass, but no full-size
   materialized service run was attempted without the certified runner.

5. **Source/status provenance.** Work was performed from the canonical Git
   checkout. The generated short snapshot is fresh, while historical status
   documents remain historical and are not used as current evidence.

## Current development verification

The refreshed disposable ARM64 binaries were built from the current source
candidate. Their retained hashes are:

- `clamd`: `695f651a2fa6cf6aaedff0c7776e92c41de658ebfc7453663ffca40bc150410f`
- `clamdscan`: `52d9e26eb0d1de76b610dc9971695996c99680acbcfb54784ccd16a4405355f3`
- `check_clamav`: `e161f7df65fc64b840b5d689d91f4027e9b6fa0cd5035d62ca5e035b98ad9234`
- `check_clamfi_quota`: `d8cb421d8aef4835070ccf6c488a0eaca6c2e6d0ace58a046516146e8279b979`

Commands and actual results:

- `CK_FORK=no CK_RUN_SUITE=cl_suite CK_RUN_CASE=required_unsupported ./check_clamav` in the disposable ARM64 container: **5 checks, 0 failures, 0 errors; exit 0**.
- `./check_clamfi_quota` in the disposable ARM64 container: **exit 0**.
- `python3 -B tools/largefile_acceptance_cases_test.py`: **8 tests passed**, including rejection of forged standalone and unretained service fixture identity bindings.
- `python3 -B tools/largefile_acceptance_case_producer_test.py`: **3 tests passed**.
- `python3 -B tools/largefile_runtime_acceptance_case_producer_test.py`: **4 tests passed** after retaining each runtime producer's scanned input artifact.
- `python3 -B tools/largefile_service_workload_check_test.py`: **19 passed, 2 Linux-only filesystem tests skipped**.
- `python3 -B tools/largefile_status_snapshot_test.py`: **12 tests passed**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md`: **exit 0**.
- `git diff --check`: **exit 0**.
- `sh tools/largefile_source_guards.sh`: **exit 0**, including the complete 597-row inventory/readiness and acceptance-control suite.
- `sh tools/largefile_release_readiness.sh --status`: **exit 1 as expected** with `597` total, `0` qualified, `143` bounded, `440` pending, `14` allowlisted unsupported, and `583` blockers.

Follow-on R04 evidence-retention correction:

- `tools/largefile_acceptance_cases.py` now requires a service-backed record
  to retain `provenance/service-inputs-before.json` in its artifact list before
  using that sidecar to bind the fixture hash. The sidecar must also carry the
  versioned object schema. This prevents an unretained identity file from
  influencing a capability record.
- `tools/largefile_acceptance_cases_test.py` adds a regression proving that an
  omitted service-input identity file is rejected and that the same record
  passes once the identity file is retained.
- `sh tools/largefile_source_guards.sh` passed after the correction. This is a
  verifier-integrity improvement only; it does not create runtime records or
  promote any capability.

Follow-on PDF parser correction: all eight string metadata callbacks and
`Pages_cb` now validate the owning scan context, options, metadata JSON, and
object before using the collection policy or deriving object pointers. The
encryption path now passes its validated crypt-filter length, and dictionary
admission restores ordinary `/CF << ... >>` delimiters after token scanning.
The current-source ARM64 disposable run passes the null-context callback and
AES crypt-filter regressions within the PDF TCase: 24 checks, 0 failures, 0
errors. Source guards and the complete local evidence-control sweep pass;
this remains development evidence and does not qualify a capability. See
`docs/largefile-task-receipts/R08-pdf-metadata-callback-2026-09-08.md`.

Follow-on milter boundary correction: the initial cached runtime lacked
`libmilter.so.1.0.1`, but the current-source shared milter/clamd build was
rerun with that library supplied only inside a disposable container. The
ordinary clean, infected, exact-limit, and limit-plus-one protocol matrix
passed with actions `a`, `r`, `a`, and `t`. A separate 4,096-byte manual-wire
case disables mail parsing only for its raw root-offset oracle and passed with
the expected tail offset 4,077, root/logical size 4,096, zero skipped
operations, `DETECTION_TERMINATED`, and milter reject. This remains ARM64
development evidence; the certified 32-GiB milter profile remains unrun.

## Explicitly unrun or blocked

- The certified 32-GiB milter run remains unrun because no authorized Linux
  x86-64 qualification runner is available. The bounded ARM64 protocol cases
  above use a disposable runtime dependency and are development evidence only.
- No current-source Linux x86-64 Release/sanitizer build, production-CVD
  workload, full-size materialized edge, privileged fanotify run, or final
  canary was claimed.
- No host software was installed. Runtime packages needed for the milter
  development probe were installed only inside disposable containers; no
  remote host was contacted, no usage reset was used, no GitHub workflow was
  changed or triggered, and no commit or push was performed.

Remaining action: obtain the authorized x86-64 runner and a reviewed
reader-backed modern OneNote API or implementation boundary; then bind the
fresh certified runs to the existing R04 case map and continue R11–R15.

State: `development-verified` for the local controls; certified release
qualification remains blocked.

Follow-on R10 legacy-wire binding correction (2026-09-08): the service
qualification script's five edge labels had been recorded as direct `clamd`
capabilities even though the commands were sent through `clamdscan` with
structured-report options. The labels now run the actual NUL-terminated
`zCONTSCAN`, `zMULTISCAN`, `zALLMATCHSCAN`, `zFILDES`, and `zINSTREAM` protocol
requests through a dedicated standard-library probe. The verifier records
these as `legacy` workloads, rejects attached structured reports, and checks
clean, exact detection, and size-limit text replies. The acceptance producer
leaves them unmapped until the legacy protocol can supply the R04-required
structured counters and alert offsets, so this correction cannot promote a
capability by itself.

The disposable ARM64 daemon check passed all six legacy detection requests,
clean SCAN, and INSTREAM size-limit behavior. The focused legacy protocol
tests passed 6/6, the service workload evidence test passed, the runtime
evidence regression passed, and source guards passed. No certified runner,
full-size evidence, host install, MCP/remote execution, usage reset, commit,
push, or GitHub workflow action was used.

Follow-on legacy-wire verifier audit (2026-09-08): the independent service
workload checker now binds each direct legacy row's recorded process exit to
the role oracle, in addition to its protocol mode, input identity, and reply
text. A regression rejects exit 0 paired with the detection oracle. The
workload suite passes 24/24 and source guards pass; this only strengthens the
evidence controls and does not change the five issue dispositions or promote
any capability.

Follow-on R13 fanotify response-boundary correction (2026-09-08): the
current-source worker now retries interrupted permission-response writes,
rejects short writes, validates queued fanotify metadata before dereference,
and routes an unaccepted response through shared `FAN_DENY`/close recovery.
The fallback denial helper also retries `EINTR`. The disposable ARM64
`clamonacc` target links successfully, the fanotify contract suite remains
9/9, and the full source/evidence guard sweep passes. This is development
evidence only; certified Linux x86-64 and privileged fanotify qualification
remain external prerequisites.

Follow-on R02 structured-report parser correction (2026-09-08): the shared
client parser now rejects unknown completion labels, requires
`DETECTION_TERMINATED` for infected verdicts, and restricts an explicitly
incomplete string verdict to the five non-detection incomplete classes. This
closes a fail-open response boundary where a malformed completion string
could otherwise be accepted as an authoritative detection or incomplete
outcome. The rebuilt current-source ARM64 `check_clamd` option-parser TCase
passed 27/27, and current-source valid-content groups passed: OneNote 2/2,
PDF corpus 1/1, ZIP 19/19, mail 16/16, and Rust OneNote 2/2. The complete
source/evidence guard sweep also passed. This remains development evidence;
certified x86-64 report transport and full-size qualification remain open.

Follow-on R10 current-source daemon integration (2026-09-08): rebuilt
`clamd`/`clamdscan` passed the repository's `clamd_test.py` integration target
15/15 in 26.277 seconds, with the embedded current-source `check_clamd` API
run passing 109/109 and a post-run `PONG`. The run used the repository signing
certificates and an internal disposable-container temporary root, and covered
startup, reload, file/stream/fdpass/multiscan, structured reports, limits,
OneNote policy, quarantine binding, and cleanup. This strengthens R10 local
development evidence without creating a certified x86-64 or full-size record.

Follow-on R02/R04 live service capture (2026-09-08): the current-source
development capture independently exercised six direct structured daemon
commands and fdpass/stream client paths across clean, detection, and limit
outcomes. It wrote and validated 24 R04-bound records, with provenance retained
under `/private/tmp/clamav-r02-service-capture`. This closes the local service
capture slice while leaving certified x86-64, full-size, privileged fanotify,
and final-canary qualification open.

Follow-on R10 ping-health correction (2026-09-08): the clamdscan health probe
now validates the exact NUL-terminated `PONG` frame after `zPING`; a successful
send alone can no longer produce a false healthy result. The client/common
targets were attempted in the existing disposable ARM64 build tree, but the
rebuild was blocked by that image's missing generated OpenSSL development
header before a fresh executable could be linked. No runtime claim, reset,
remote execution, host install, commit, push, or workflow action was made.

Follow-on R10/R13 on-access ping-health correction (2026-09-08): both
on-access client health paths now read and require the exact NUL-terminated
`PONG` frame after `zPING`; a successful write alone cannot report a healthy
connection. Source/evidence guards pass. A translation-unit compile was
attempted in the existing disposable ARM64 image but stopped at that image's
missing libcurl development header, so no fresh binary or runtime claim was
made. Certified privileged Linux x86-64 evidence remains required. No host
install, remote execution, usage reset, commit, push, or workflow action was
used.

Follow-on R10 on-access transport correction (2026-09-08): fixed the
unreachable `sent && errno == EINTR` retry condition in `onas_sendln()` so an
interrupted zero-byte send is retried. Source guards and the complete local
control suite pass; the cached image still lacks libcurl development headers,
so no fresh on-access binary or runtime qualification was claimed. No host
install, remote execution, usage reset, commit, push, or workflow action was
used.

Follow-on R10 on-access descriptor correction (2026-09-08): regular-file
stream preflight now rewinds descriptor 0 as well as every other descriptor,
preventing a suffix-only scan when standard input is a regular file. Source
guards and local controls pass; the disposable image still lacks libcurl
development headers, so no binary or runtime qualification was claimed.

Follow-on R13 excluded-event response correction (2026-09-08): fanotify's
excluded permission-event path now retries `EINTR` for `FAN_ALLOW` and routes
short or failed writes through `FAN_DENY`/close recovery. Source guards and
local controls remain green; no privileged Linux x86-64 runtime evidence was
claimed.

Follow-on R10 on-access descriptor-passing correction (2026-09-08):
`FILDESREPORT` now retries interrupted `sendmsg()` and rejects a short payload,
so a missing or incomplete ancillary FD transfer cannot be treated as a
successful scan submission. Source controls remain green; no fresh on-access
binary or certified runtime evidence was claimed.

The isolated fanotify object compile was also attempted in the existing
disposable ARM64 build tree and was blocked before compilation by its missing
generated OpenSSL development header (`openssl/opensslconf.h`). No dependency
was installed or downloaded.

The shared legacy `FILDES`/`FILDESREPORT` helper now also retries `EINTR` and
requires the complete one-byte `sendmsg()` payload. A short or interrupted
ancillary-data send therefore remains fail-visible for clamdscan and other
common-client callers instead of being accepted as successful descriptor
delivery. This is source/control evidence only; a fresh object/runtime build
still requires the authorized runner or a disposable image with the missing
development headers.

Fresh current-source object verification succeeded in the disposable ARM64
container: `clamonacc/client/protocol.c.o` and `common/clamdcom.c.o` both
compiled after the missing development packages were installed inside that
container. The complete on-access link was not claimed because Cargo then
attempted to refresh unavailable Git dependencies; certified x86-64 runtime
evidence remains pending.

The shared legacy stream sender now performs regular-file size admission and
rewind checks for descriptor 0 too. Its former `0 != fd` guard skipped those
checks when standard input referred to a regular file, which could permit a
suffix-only or over-limit stream. This is source/control evidence only; fresh
shared-client runtime evidence remains pending on the authorized runner or a
disposable image with the missing development headers.

After adding Git to the disposable container, the complete current-source
`clamonacc` target built and linked at 100% with Clang 16.0.6 and Rust 1.97.1,
with UnRAR, Milter, fanotify, and shared libclamav enabled. The resulting
ARM64 `clamonacc` hash is
`b1fdaa8d73a29668c097577fd9ec163fa0d221e45aa519e96e7340ede109d8ef`, and the
linked `libclamav.so.14.0.0` hash is
`a656c48e7ecb857291ea96fde13a08c1fa6c6b636e50a1cadece493ec8d1dfda`. With
`-c /dev/null`, the freshly linked `clamonacc --help` exited 0 and reported
`1.5.3-largefile-devel`. This remains ARM64 development evidence, not
certified x86-64 or full-size qualification evidence.

The rebuilt `check_clamd` client stream-accounting group passed 10/10 in the
disposable ARM64 container. The group includes the descriptor-0 regular-file
regression, verifying rewind from a nonzero starting offset and complete
`zINSTREAM` payload delivery, plus the existing over-limit and descriptor
error checks. This is focused development evidence, not certified x86-64 or
full-size qualification evidence.

Shared `sendln()` now retries interrupted `send()` calls when they return
`-1`/`EINTR`, and a deterministic socketpair regression verifies that a
blocked payload completes after the peer drains. The rebuilt client
stream-accounting group passed 11/11 in the disposable ARM64 container,
including the new transport case. This is development evidence, not
certified x86-64 or full-size qualification evidence.

Follow-on R06/R03 current-source implementation slice (2026-09-09): the
audited pinned OneNote parser was vendored at its recorded revision and given
a sequential reader boundary with 64 KiB refills, short-read handling, typed
I/O/resource errors, and a 256 MiB per-payload materialization guard. The
ClamAV scanner now feeds that boundary from `FMapReader` while retaining the
legacy fallback, attachment spool, callback stop, cleanup, and status
propagation paths. The outer whole-input admission cap remains fail-visible;
it was not raised. The vendored parser suite passed 13/13 unit tests and 4/4
integration tests, including deliberate short reads and a logical
256 MiB-plus padded input. A fresh x86-64 CMake relink and focused
`rust_onenote` run passed 2/2.

The same current-source sanitizer build also repaired the mixed C/Rust test
link contract: ASan/UBSan runtimes are supplied only for Cargo test builds,
and preloaded only through the Rust test executable's target runner. Focused
Rust sanitizer CTest passed 1/1; focused quota, clamscan, clamd, freshclam,
sigtool, MBR, and MHTML controls passed. The complete configured CTest pass
was not called green because the broad `cl_suite` hit a 600-second timeout and
two repo-wide controls exceeded the disposable container's CTest time limits;
the exact broad-suite case is still isolated work.

This advances implementation and development verification for issues 2 and
3 while preserving the five-issue dispositions: no certified runner,
full-size materialized evidence, bytecode format-8 artifact, capability
promotion, usage reset, commit, push, or GitHub workflow action was used.

Follow-on R06 aggregate-materialization refinement (2026-09-09): the
vendored OneNote reader now accounts for the cumulative size of all
parser-owned payload buffers retained by a section, with fallible slice and
stream reservations under the explicit aggregate 256 MiB budget. The parser
unit suite passed 14/14 and its integration suite passed 4/4, including the
new cumulative-limit regression. This closes the reader's previously
unaccounted aggregate-buffer gap at development level; the outer admission
cap, valid late-content fixture, quota/fault integration, and certified
full-size evidence remain open.

The full `libclamav_rust` consumer crate passed `cargo check --locked` after
this refinement in the disposable x86-64 environment, so the updated parser
boundary compiles through the scanner-facing integration as well as its
standalone parser tests.

Follow-on inventory control repair (2026-09-09): the generated large-file
inventory was refreshed after the vendored reader and build-script line
changes. `sh tools/largefile_source_guards.sh` then passed with all 597
capability rows, release-readiness controls, acceptance schemas, and source
guards green; no capability status was promoted.
