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

Follow-on R09 GGUF current-format slice (2026-09-10): the bounded GGUF
geometry table now recognizes the current GGML `TQ1_0`, `TQ2_0`, `MXFP4`,
`NVFP4`, `Q1_0`, and `Q2_0` tensor IDs with their exact block sizes. The
required-unsupported TCase adds a table-driven one-block admission regression
for all six types. This is an implementation and source-contract advance for
issue 2, with no claim of linked current-source execution or capability
qualification; the certified runner, full model semantics, full-size
materialization, acceptance records, and release gate remain open.

Follow-on R09 raw-only status-boundary correction (2026-09-10): the
`cli_magic_scan()` raw-only fast path now merges its matcher result with a
previously recorded parser/incomplete status instead of overwriting it. This
keeps recognized Python/ignored inputs fail-visible when parsing is disabled,
while preserving a malware detection from the raw matcher. The full local
tools suite passed 145 tests with 2 expected skips, the snapshot check passed,
`git diff --check` passed, and `sh tools/largefile_source_guards.sh` passed.
No capability was promoted; certified runner, full-size evidence, and linked
current-source C execution remain open.

Follow-on R09 bounded Python-bytecode parser (2026-09-10): recognized Python
compiled inputs now pass through a non-executing marshal structural walker
with bounded object count, recursion depth, length, reference, and fmap
offset checks. The dispatcher merges the parser result with raw matching, so
malware detection remains visible while malformed or unsupported marshal data
remains incomplete and non-cacheable. Required-group fixtures cover truncated
input, legacy and modern code-object layouts, and raw-detection precedence.
The 145-test local tools
suite (2 expected skips), snapshot check, `git diff --check`, and full source
guard passed. No capability was promoted; independent format-8 fixtures,
certified runner, full-size evidence, and linked current-source C execution
remain open.

Follow-on R04 lifecycle fixture-binding correction (2026-09-11): lifecycle-bound
acceptance records now require a named `fixture_role` and the
`provenance/service-inputs-before.json` identity sidecar. A retained fixture
artifact alone cannot satisfy a record that claims daemon health/cleanup
lifecycle evidence. Added regressions for missing role and missing sidecar;
the focused acceptance schema passes 12/12, the full tools suite passes
145 tests with 2 expected skips, and the complete source guard passes. The
authoritative acceptance-record file remains empty; no capability status was
promoted and certified Linux x86-64/full-size qualification remains blocked.

Follow-on R09 GGUF row-shape refinement (2026-09-11): the bounded model
geometry checker now validates the innermost row dimension against each
quantization block size, rejecting a `16x2` Q4_0 tensor whose total element
count would otherwise appear block-aligned. The required-group regression is
registered and the source/control sweep passes. No fresh linked C execution is
claimed because the available ARM64 Docker image lacks the test/development
libraries and no package installation was authorized; full tensor semantics,
certified x86-64, and release qualification remain open.

Follow-on R09 GGUF tensor-name boundary refinement (2026-09-11): the bounded
model parser now rejects names at the reference 64-byte `GGML_MAX_NAME` limit
before skipping their payload. The regression uses a complete descriptor and
payload so it exercises the name rule rather than truncation; the source/control
sweep passes. No linked C execution is claimed because the available ARM64
Docker image lacks the test/development libraries and no package installation
was authorized.

Follow-on R09 TFLite metadata-buffer vector coverage hardening (2026-09-11):
the bounded FlatBuffer walk now explicitly documents and tests
`Model.metadata_buffer` as a scalar `int32` vector, matching the schema, and
keeps each buffer index out of the table-offset walker. The required-
unsupported group adds a valid model with two buffer tables and metadata-buffer
index one. Source/evidence guards remain green; linked current-source C
execution, certified x86-64, full-size evidence, and release qualification
remain open.

Follow-on R09 TFLite metadata-buffer index-binding hardening (2026-09-11):
the bounded FlatBuffer walk now checks every signed metadata-buffer entry
against the declared buffers-vector count and rejects negative or out-of-range
indices as incomplete. The required-unsupported group adds a fail-visible
regression that changes the valid fixture's index to two while only entries
zero and one exist, requiring `CL_EPARSE`, cleared verdict, and cache taint.
Source/evidence guards remain green; linked current-source C execution,
certified Linux x86-64, full-size evidence, and release qualification remain
open.

Follow-on R10 argument-separator parser hardening (2026-09-11): argument-
taking clamd commands now require the protocol's literal space separator, so
malformed `SCANfoo` input is rejected instead of being dispatched with its
first path byte discarded. The existing daemon compatibility matrix covers
the malformed form in prefixed NUL/newline and legacy packet modes and requires
`UNKNOWN COMMAND`. Source/evidence guards and current-source daemon tests pass;
certified/full-size ingress records and R04 qualification remain open.

Follow-on R09 signed TFLite metadata-buffer index hardening (2026-09-11): the
bounded FlatBuffer walk now decodes `Model.metadata_buffer` entries as signed
`int32` values before buffer-count admission, explicitly rejecting negative
indices. The required-unsupported group adds a valid-shape fixture with an
`-1` entry and requires `CL_EPARSE`, a cleared verdict, and cache taint. Source
and local control checks remain green; the linked ARM64 required-unsupported
group passed 38/38. Certified Linux x86-64, full-size evidence, and release
qualification remain open.

Follow-on R09 fuzzy-image build correction (2026-09-11): a disposable
current-source CMake build exposed an ambiguity in `u64::from(...)` after the
pixel-count reservation added `num_traits::NumCast` to scope. The two `u32`
image dimensions now widen explicitly before checked multiplication, restoring
Rust compilation without changing the admission policy. The final disposable
ARM64 current-source build and linked library/daemon checkpoint passed; no
capability promotion or certified/full-size claim is made.

Follow-on R09 TFLite compile correction (2026-09-11): the same disposable
current-source build exposed a C redeclaration in the TFLite field helper: its
local vtable offset reused the `field_offset` output-parameter name. The local
was renamed to `vtable_field_offset`; behavior and admission policy are
unchanged. The final ARM64 required-unsupported group passed 38/38; certified
x86-64/full-size qualification remains open.

Follow-on R09 AI-model test/build corrections (2026-09-11): AI-model unit
fixtures now explicitly enable parser execution; GGUF final-payload admission
no longer requires padding after the final tensor; and Python/GGUF raw-marker
fixtures use their actual marker offsets while checking parser status separately
from `verdict_out`. The linked ARM64 required-unsupported group passed 38/38;
execution remains local development evidence only.

Follow-on daemon protocol test cleanup (2026-09-11): the bounded legacy-reply
parser now treats clamd's documented `Excluded` directory result as a clean
skip, while continuing to reject unknown terminal text. The bounded path-request
unit fixture now starts with the caller's normal clean-state `printok=1`, so it
tests command framing without asserting an unrelated initial-state transition.
With the build copied to a container-native filesystem, all 15/15 clamd tests
passed after the correction. No certified x86-64 or full-size qualification
claim is made.

Follow-on R09 Python backing-read status hardening (2026-09-11): the bounded
marshal reader now preserves an in-range fmap backing-read failure as
`CL_EREAD` with sticky incomplete/non-cacheable state, while short/truncated
marshal ranges remain `CL_EPARSE`. The public regression is registered in both
ordinary and required-unsupported groups; host tests passed 147 with 2 expected
skips, source guards passed with 597 capability bindings, and the refreshed
inventory/snapshot checks passed. No linked current-source C execution is
claimed because the available Docker images lack JSON-C and Check development
headers; certified x86-64, full-size, sanitizer, production-service, and final
release qualification remain open.

Follow-on R10 on-access timeout normalization (2026-09-11): curl-backed
on-access send/receive waits now normalize signed timeout inputs before the
unsigned socket-wait helper, and curl-backed receive select failures preserve
`CURLE_RECV_ERROR` instead of leaving `CURLE_AGAIN` as the terminal status.
The existing descriptor-backed reader uses the same normalization. Host
tests passed 147 with 2 expected skips; full source guards passed with 597
capability bindings, refreshed snapshot/inventory checks passed, and the
current source-manifest SHA-256 is
`5183c325e03e21e3fd09e6f01723d4a1bc100104484857198fd3971daccaed94`. No
capability promotion, remote execution, MCP-SSH, usage reset, commit, push,
or workflow action was used.

Follow-on R10 shared command-send width hardening (2026-09-11): `sendln()`
now stores the native `ssize_t` result from `send()` while draining its
unsigned wire-length input, preventing a large successful write from being
misclassified through an `int` narrowing conversion. Source and host controls
remain the verification basis; linked current-source runtime, certified
x86-64, full-size service parity, and release qualification remain open.

Follow-on R10 milter send deadline and spool-write retry (2026-09-11 UTC):
`nc_send()` now establishes one deadline for a complete nonblocking payload
instead of resetting the deadline after each partial write, and the local
milter temp-file spool retries `EINTR` without abandoning the message. Source
and host controls remain the verification basis; linked current-source
milter execution, certified x86-64, full-size service parity, and release
qualification remain open. The stable current source-manifest SHA-256 is
`2e00bba6b8dadca33d8d5e17eca3679018ca48c37215ab4ab8d5ac1dcc98429a`.
Receipt:
`docs/largefile-task-receipts/R10-milter-send-deadline-spool-write-2026-09-11.md`.

Follow-on R06 modern-reader boundary verification (2026-09-11): the current
vendored OneNote parser compiled offline through a temporary out-of-tree
manifest, passed 61/61 library tests, and passed 2/2 reader-boundary tests
covering short reads and a logical `256 MiB + 1` input without materializing
that size. The normal package test remains blocked by the uncached offline
`insta` dev dependency; no qualification or capability promotion follows.

Follow-on R10 milter compile correction (2026-09-11): restored the local
`strerror_print` scratch buffer in `nc_send()` after the deadline hardening
slice exposed a current-source compile defect. The disposable Docker
toolchain passed warning-free syntax checking for `clamav-milter/netcode.c`,
and the source guard now protects the error branch. No capability promotion
or linked-runtime claim follows.

Follow-on R10 milter deadline enforcement (2026-09-11 UTC): `nc_send()` now
checks its single end-to-end deadline before every nonblocking `send()`, so a
continuously writable socket cannot extend the timeout through repeated
successful partial writes. The ten changed ingress units pass disposable
warning-as-error syntax checks; host tooling passes 147 tests with 2 expected
skips; source guards, inventory freshness, snapshot validation, and
`git diff --check` pass. Refreshed source-manifest SHA-256:
`7367697b6324da35cfa800e0f42c280b208f8ed9e6266e1b943411b907d935f7`.
No capability promotion or release qualification follows.

Follow-on R10 milter guard precision (2026-09-11 UTC): the source controls
now prove that the deadline checks occur before the real `send()` and
`sendmsg()` operations, rather than merely detecting a wait-loop check. The
guard sweep, host suite (147 passed, 2 expected skips), focused syntax check,
inventory/snapshot validation, and `git diff --check` passed. Refreshed
source-manifest SHA-256:
`07b9f9b1f92a71c9b361f004de4b3c5e0de413821231a3d4c4bb2adada8ce4d8`.
No capability promotion or release qualification follows.

Follow-on R10 milter FD-passing deadline enforcement (2026-09-11 UTC):
`nc_sendmsg()` now checks its single end-to-end deadline before every
`sendmsg()` retry, including repeated `EINTR` retries. The focused milter
syntax check passed with warnings treated as errors; host tooling passed 147
tests with 2 expected skips; source guards, inventory freshness, snapshot
validation, and `git diff --check` passed. Refreshed source-manifest SHA-256:
`77146a74752dec7e1bc49b30d32af4193ca46a86c92ff3a9df905690aab3981b`.
No capability promotion or release qualification follows.

Follow-on R10 on-access FD-pass timeout parity (2026-09-11 UTC): the local
FILDES socket is now nonblocking; in-progress connect, command bytes, and the
SCM_RIGHTS descriptor send are bounded by the configured
`OnAccessCurlTimeout`, with deadline checks before the actual `send()` and
`sendmsg()` operations and distinct timeout/write status. Focused on-access
syntax checks passed with warnings treated as errors; the host suite passed
147 with 2 expected skips; source guards, focused protocol/service controls,
inventory, snapshots, acceptance map, and `git diff --check` passed. The
current source-manifest SHA-256 is
`1f16a6014a02be9857f41866926c15c39db282459d69baa9aaa3eb65923e4160`.
No capability was promoted; certified x86-64, full-size service, R03 runner,
R04 records, sanitizer, and final release qualification remain open. Receipt:
`docs/largefile-task-receipts/R10-onaccess-fdpass-timeout-2026-09-11.md`.

Follow-on R10 on-access FD-pass transport hardening (2026-09-11 UTC):
interruptible connect and writable-send waits now rebuild their select state
and remaining deadline after `EINTR`; raw FILDES command and descriptor sends
also suppress `SIGPIPE` where the platform supports `MSG_NOSIGNAL` or
`SO_NOSIGPIPE`. Focused warning-as-error syntax, host tests (147 passed, 2
expected skips), source guards, inventory/snapshots, and `git diff --check`
passed. Current source-manifest SHA-256:
`3a29e00559104dd7328e4bd8e1bd264c38fc7f2e238cb3aafa2332433773a119`.
No capability promotion or release qualification follows.
