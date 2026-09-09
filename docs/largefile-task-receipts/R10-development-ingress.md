# Task receipt: R10 development ingress smoke

Task ID / parent milestone: `R10` / `R00`

Scope: verify that the current roadmap checkout produces a runnable scanner
binary and a real detection through the CLI boundary. This is a development
smoke slice, not ingress qualification.

Prerequisites verified:

- Canonical source: `/Volumes/512gbNVME/github-external/ClamAV-32gb`.
- Branch: `largefile-roadmap-qualification`.
- Current-source ARM64 Debug build: `/private/tmp/clamav-largefile-build`.
- Build and runtime dependencies were used only inside disposable Docker
  containers; no host installation was performed.

Observed behavior:

- The rebuilt `clamscan` reports `ClamAV 1.5.3-largefile-devel`.
- `clamscan --help` exits successfully.
- A temporary fuzzy-image signature for the repository `logo.png` produces
  the expected `logo.png.good.UNOFFICIAL FOUND` detection and exit code 1.
- The production-linked Rust fuzzy-image test group passes 9/9.
- The coherent build's `clamd` starts with a disposable Unix-socket
  configuration, loads the temporary signature, and responds `PONG` to
  `clamdscan --ping=1:1`.
- Current-source `clamdscan` detects the same logo through the file path and
  stdin/stream boundaries with exit code 1, and scans `README.md` clean with
  exit code 0. Structured reporting was also exercised against a fresh
  current-source daemon: infected path mode returns exit code 1 with
  `DETECTION_TERMINATED` and the exact alert, clean path mode returns exit code
  0 with `COMPLETE`, and stream mode returns the expected detection report.
  The path-mode result required and now includes a regression fix: the client
  had treated `sendln()`'s zero-on-success return as a failed request. A fresh
  daemon run now exercises `CONTSCANREPORT`, `MULTISCANREPORT`, and
  `ALLMATCHSCANREPORT`; all three return the expected detection boundary
  result, while MULTI emits the daemon's aggregate/member frames. The
  observed reports are development smoke output, not retained R04 acceptance
  records.
- A fresh current-source `clamd`/`clamdscan` smoke also covered file, stdin
  stream, and fd-passed detection with the rebuilt structured-report client.
  All three returned exit code 1, emitted the exact
  `LargeFile.R10.Live.Detection.UNOFFICIAL FOUND` line, and wrote
  `DETECTION_TERMINATED` reports with the exact alert and offset 7. This
  development daemon used historical limits because the ARM64 build
  intentionally refuses certified large-file admission.

Regression coverage:

- `check_clamd` was rebuilt with a socketpair regression test that exercises
  successful `CONTSCANREPORT`, `MULTISCANREPORT`, and `ALLMATCHSCANREPORT`
  requests through framed report parsing. The full disposable suite reached
  107 checks; its 73 failures were daemon-command cases requiring the
  unavailable `clamd-test.socket`, not this local client regression.
- The current-source static `check_clamd` runner now supports the same
  `CK_RUN_SUITE`/`CK_RUN_CASE` selection used by the other test runner. Its
  filtered option/admission group passed 27/27 checks and its stream/fd-passing
  accounting group passed 7/7 checks.
- A fresh current-source static `clamd` was started against a writable
  disposable Unix socket under the legacy non-large-file envelope. The live
  command group passed 69/69 checks, and the documented high-queue concurrent
  stress profile passed 4/4 checks. The same daemon correctly rejects the
  large-file envelope on ARM64 with the explicit Linux x86-64 admission guard.
- The milter-enabled shared Debug build exposed and fixed a missing
  `clamdcom.h` declaration include in `clamav-milter/clamfi.c`; the rebuilt
  target no longer emits the implicit `scan_report_completion_name()` warning.
  With `MILTER_DEVELOPMENT_LEGACY_LIMITS=1`, the real current-source milter
  protocol harness passed clean, infected, exact-limit, and limit-plus-one
  actions (`a`, `r`, `a`, `t`) against the live disposable clamd. The default
  certified 32-GiB milter profile remains unchanged and was not claimed on
  ARM64.
- The registered milter quota target was built from the same current source,
  and CTest ran both `clamav_milter_quota` and `clamav_milter_protocol` with
  2/2 passing. The protocol test used the explicit development legacy-limit
  switch because ARM64 intentionally rejects the certified large-file
  envelope.
- The scan-API callback regressions are isolated in a dedicated
  `cl_callback_api` Check case with the engine fixture they require. The
  static ARM64 development runner passed both legacy and modern callback
  fail-visible tests (2/2) without fork isolation; the broad `cl_api` matrix
  remains an environment-limited development probe.
- Four parser fail-visible regressions are isolated in the dedicated
  `parser_regressions` Check case. The static ARM64 development runner passed
  the nested fmap/force-to-disk, InstallShield MSI, truncated InstallShield
  metadata, and compressed-output temporary-limit checks (4/4).
- The shared `dsreport()` path now binds the human-readable detection line to
  the structured report's `last_alert`, including direct stdin reports, and
  the service qualification script explicitly requests infected output and
  writes the correct `CVDCertsDirectory` key. The rebuilt `check_clamd`
  regression captures the exact signature line for report-mode path requests
  and rejects infected frames with a missing or empty alert instead of
  emitting a bare `FOUND` line. The parallel IDSESSION report helper applies
  the same fail-closed rule.
- The public stream-client path now accepts a missing option table and routes
  it through the shared bounded 32-GiB default, instead of rejecting the
  request before the common limit helper can apply that default. A socketpair
  regression covers the resulting `zINSTREAM` wire framing and is registered
  in `check_clamd`; the source guards and current-source `clamdcom.c` compile
  pass. A direct API smoke harness linked against the refreshed common archive
  also passes the NULL-options framing check. The cached test container has no
  Check framework header, so the updated unit-test object was not rebuilt in
  this environment.

Full-size/certified evidence produced, or explicitly not run: no Linux
x86-64 Release/sanitizer evidence, R04 daemon/service acceptance record,
exact 32-GiB materialized run, production CVD, certified milter, or on-access
evidence was produced. The roadmap requires those records under R04/R10-R14.

Remaining failures / next slice: retain current-source daemon and clamdscan
records on an authorized runner; then exercise known-size and unknown-size
ingress boundaries, clean/detection/limit outcomes, and service health. The
R03 ARM64 build is development evidence only.

State: `development-verified`; release readiness remains blocked.

Follow-on Sonic1 sanitizer ingress smoke (2026-09-09):

- The C ASan/UBSan `clamd`/`clamdscan` build from the repaired remote source
  graph was exercised over direct TCP, framed `--stream`, and Unix-socket
  `--fdpass` paths. Each path returned clean exit `0`/`OK` for the clean 1 MiB
  input and detection exit `1` with the exact
  `LargeFile.POC.32g-edge.UNOFFICIAL FOUND` alert for the marker input.
- `clamdscan --ping=1` returned `PONG`; the daemon remained healthy after the
  TCP and stream probes, and the fd-passing daemon also remained healthy until
  it was stopped after its checks. No ASan/UBSan diagnostics were emitted.
- Retained sanitizer report hashes are recorded in the R03 receipt for direct
  TCP (`00ceb5...` clean, `59d3e3...` detection), framed stream
  (`af1cd7...` clean, `afa9ba...` detection), and fd passing
  (`2dcfa1...` clean, `e9abe2...` detection). These are development artifacts
  and do not replace certified R04/R10 records.

Follow-on current-source daemon/client smoke (2026-09-08): the refreshed
ARM64 static build relinked `clamd` and `clamdscan` after the PDF and ingress
changes. The repository's three daemon checks passed 3/3 in 2.109 seconds:
`test_clamd_00_version` reported `ClamAV 1.5.3-largefile-devel`,
`test_clamd_01_ping_pong` returned `PONG` with exit 0, and
`test_clamd_02_clamdscan_version` reported the same daemon version. Startup
also logged the configured 32-GiB contiguous ceiling, 64-GiB temporary and
logical-scan ceilings, and 256-GiB matcher-work ceiling. The fresh binary
hashes are `clamd`:
`46fd21fa6e3de7045ee42429f8f13c3a27dba7c4704d6109f7c687453b6572c4` and
`clamdscan`:
`8e142b0ee6f49f8e65430590516ebd17464f1b1235b6b57f017ee4e504a52e84`.
This is current-source ARM64 development evidence; no R04 acceptance record
or certified/full-size claim is created.

Follow-on current-source structured service capture (2026-09-08):
`tools/largefile_development_service_capture.py` produced 24 records under
`/private/tmp/clamav-r10-current-capture-20260908`. All six direct daemon
report commands (`SCANREPORT`, `CONTSCANREPORT`, `MULTISCANREPORT`,
`ALLMATCHSCANREPORT`, `FILDESREPORT`, and `INSTREAMREPORT`) and both client
transports (`clamdscan --fdpass` and `clamdscan --stream`) were exercised over
clean, detection, and MaxFileSize-limit fixtures. The outcome matrix was
8 `COMPLETE`/exit 0, 8 `DETECTION_TERMINATED`/exit 1, and 8
`LIMIT_INCOMPLETE`/exit 2. The capture completed with exit 0, and an
independent `largefile_acceptance_cases.py --check-records` pass revalidated
all 24 records, retained artifacts, and hashes. The acceptance-record SHA-256
is `c3ef8de78fb9ecad472ebc593203dca51c57334b797a51240465805389b86169`;
the source-manifest SHA-256 is
`7852ed3eb1170bf4f15887a3d4ab70fe6ce026a2dc7d9040770e361ee0257fcf`; and
the build-identity SHA-256 is
`3e2038ae52d954e1d32a774b927e588fc59f59fecf851d89e60b08a810ad9f41`.
This remains ARM64 Debug development evidence and does not create
authoritative R04 records or a certified/full-size claim.

Legacy clamd wire binding correction (2026-09-08): the qualification script
previously recorded `edge_contscan`, `edge_multiscan`, `edge_allmatch`,
`edge_fildes`, and `edge_instream` as service workloads while invoking the
`clamdscan` client with structured-report options. Those labels were therefore
not proof of the direct `clamd` legacy commands named by the R04 map. The
script now invokes a dedicated standard-library probe with the actual
`zCONTSCAN`, `zMULTISCAN`, `zALLMATCHSCAN`, `zFILDES`, and `zINSTREAM` wire
commands, normalizes both NUL- and LF-terminated replies, and validates clean,
detection, and size-limit outcomes. The workload verifier types these rows as
`legacy` and rejects a structured report on them; the acceptance producer does
not promote them because the legacy protocol has no structured counters or
native alert offset. Historical workflow status aliases are retained only for
compatibility and are not evidence bindings.

The disposable ARM64 daemon probe exercised all six direct legacy commands on
a detection fixture, and separately passed clean SCAN plus an INSTREAM
size-limit reply (`Exceeded max scan size ERROR`). The focused legacy protocol
tests passed 6/6; the service workload and service/runtime evidence regression
suites passed. This closes the false-binding defect in the local qualification
tooling, but remains development evidence: the certified x86-64 runner,
full-size inputs, and structured R04 records are still required.

Application-facing regression follow-up (2026-09-08): the four registered
CLI/service targets were rerun from the current-source build. `clamscan`,
`freshclam`, and `sigtool` passed; the first CTest invocation's `clamd` target
was invalidated by its host-mounted temporary directory rejecting the daemon's
socket permission operation, and `check_clamd` also lacked `libsubunit.so.0`.
With the same build artifacts, a container-local temporary directory, and the
missing runtime library supplied only inside the disposable container, the
complete `clamd_test.py` target passed 15/15 in 31.470 seconds. Its embedded
`check_clamd` API run passed 107/107, and the post-run PING returned `PONG`.
The successful run verified daemon startup, reload and scan modes, report
client behavior, limit handling, OneNote configuration handling, quarantine
path handling, and daemon health. No source or qualification status changed;
this remains ARM64 development evidence.

CTest temporary-root portability follow-up (2026-09-08): the repository now
accepts the cache path `CLAMAV_TEST_TMP`; when set, the unit-test environment
uses that directory for `TMP` on both Windows and non-Windows builds, creating
it during configuration. A fresh disposable ARM64 reconfiguration with
`CLAMAV_TEST_TMP=/tmp/clamav-ctest-temp` regenerated the test environment with
that exact path. The registered `clamd` CTest target then passed 1/1 in 30.99
seconds (the target's direct suite was 15/15, including embedded `check_clamd`
107/107 and a final `PONG`). This closes the host-mounted temporary-directory
portability failure observed in the first CTest invocation without changing
the default build behavior or any qualification status. Systemd was disabled
only in the disposable CMake cache; no host packages were installed.

Manual-wire milter boundary follow-up (2026-09-08): the exact bounded protocol
fixture initially looked like an offset/report defect because its mail-like
headers caused the marker to be found in a child mail layer. The fixture now
disables mail parsing only for this raw-ingress oracle and enables debug output
for the disposable daemon, while leaving the normal four-case protocol matrix
unchanged. The temporary database signature-name matcher also accepts ClamAV's
`.UNOFFICIAL` suffix. In a disposable ARM64 runtime with
`MILTER_DEVELOPMENT_LEGACY_LIMITS=1` and a 4,096-byte wire limit, the manual
case passed: 4,044 body bytes, 4,096-byte root, marker offset 4,077,
`DETECTION_TERMINATED`, 4,096 logical bytes, zero skipped operations, and
structured `last_alert_offset=4077`; the milter returned reject (`r`). The
ordinary clean, infected, exact-limit, and limit-plus-one matrix was rerun and
passed with actions `a`, `r`, `a`, and `t`. This remains ARM64 development
evidence only; the certified 32-GiB profile and R04 acceptance records remain
open.

Legacy-wire verifier status correction (2026-09-08): the independent service
workload verifier now requires each `legacy` row's recorded process exit to
match the role oracle in addition to checking the protocol mode, input
identity, and reply text. A contradictory status could previously pass if its
text reply looked valid. The new regression rejects a clean status paired with
the detection oracle; the focused workload suite passes 24/24, the direct
legacy protocol suite passes 6/6, and the full source-guard sweep passes.
This is an evidence-integrity correction only and does not promote a record.

Current-source rebuild follow-up (2026-09-08): the cached disposable ARM64
toolchain was missing architecture-specific development headers, so the
current `clamscan` target was rebuilt in a temporary named container after
installing `libssl-dev`, `libjson-c-dev`, `libcurl4-openssl-dev`, and
`zlib1g-dev` inside that container only. The rebuild completed with
`cmake --build ... --target clamscan -j2`. The resulting `clamscan` hash is
`f24d6f8506b9bb3ce7c2b7078145ccb191586688033e6babb26063bc4621b524`, the
`libclamav.so.14` hash is
`ee3674672f8d4a11811b2c22cc89c176f4f52d735b5ecaa1f4ee328222a56e68`, and the
build-cache hash is
`0d801d82a3482e3e569039a22eabe5197f344d72e2eaa3336de271dc363c2f2e`.
The rebuilt scanner reported `ClamAV 1.5.3-largefile-devel` and scanned the
repository `logo.png` cleanly as `OK`. The temporary container was removed;
this remains ARM64 development evidence and is not a certified build.

Startup-health qualification correction (2026-09-08): `start_service()` had
passed `--wait` together with `--ping` to `clamdscan`. In this client, that
combination performs a successful ping and then enters the normal scan path;
with no input, it can scan the qualification process's current directory
while the service is merely being polled. The loop now uses ping-only mode and
keeps its existing bounded retry policy. `sh -n` and the full source-guard
sweep pass, including guards that reject the old option combination. This is
an application-facing R10 qualification fix; the certified runner and
retained R04 records remain required.

Current-source daemon integration follow-up (2026-09-08): after the shared
structured-report parser correction, `clamd` and `clamdscan` were rebuilt from
the canonical source in the disposable ARM64 toolchain. The rebuilt hashes
were `b623444aa983ad960b91c90c89d051a806c93840b634f859c20fa33f4bd6730f`
(`clamd`), `16457afc7887e1648a87812838881a3c644fba3b0e9748b0f249bcbd5a130823`
(`clamdscan`), and
`5af780e705eda9fd3a70a8528e722395b7dd82fa0c1a81707a930466c1bb8d70`
(`check_clamd`). With the CTest signing-certificate path and an internal
container temporary root, `clamd_test.py` passed 15/15 in 26.277 seconds;
its embedded current-source `check_clamd` API run passed 109/109 and returned
post-run `PONG`. This verifies daemon startup, reload, file/stream/fdpass and
multiscan paths, structured report handling, limit outcomes, OneNote policy,
quarantine source binding, and cleanup. It remains ARM64 development
evidence, not certified 32-GiB qualification.

Ping-response validation follow-up (2026-09-08): `clamdscan --ping` now
reads the daemon frame after sending `zPING` and accepts health only for the
exact NUL-terminated `PONG` response. A successful write, truncated reply,
or different command response now closes the socket and follows the existing
bounded retry path instead of printing a false `PONG`. The current-source
client/common targets were rebuilt as far as the cached ARM64 build allowed;
the full relink stopped earlier on the container's missing generated
OpenSSL development header, so no new binary hash or runtime qualification is
claimed. This is an application-facing R10 correction; certified x86-64
health and ingress evidence remain required.

On-access ping-response validation follow-up (2026-09-08): the on-access
client's remote-detection and retrying health paths now share an exact,
NUL-terminated `PONG` response check after `zPING`. A successful write,
truncated reply, unexpected command response, or closed socket now follows the
existing error/retry path instead of being reported as a healthy clamd
connection. The changed translation unit passed source review and the
repository's source/evidence guards; a full on-access relink was not possible
because the cached ARM64 image has no libcurl development header, so no fresh
binary or runtime qualification is claimed. Certified Linux x86-64 privileged
on-access evidence remains required.

On-access send EINTR correction (2026-09-08): `onas_sendln()` now retries a
zero-byte send interrupted by `EINTR`; the former `sent && errno == EINTR`
condition was unreachable inside the `sent == 0` branch and could turn an
interrupt into a false transport failure. The source guard and full local
control suite pass. The cached ARM64 image still lacks the libcurl development
header needed for a fresh on-access object, so no binary or runtime
qualification is claimed.

On-access descriptor rewind correction (2026-09-08): the stream preflight now
rewinds every regular-file descriptor after `fstat()`, including descriptor 0.
The previous `0 != fd` condition could scan only the suffix when a valid
regular file occupied standard input. The source guard and local control suite
cover the corrected boundary; a fresh on-access object remains unavailable
because the disposable image lacks the libcurl development header.

On-access descriptor-passing correction (2026-09-08): the `FILDESREPORT`
ancillary-data send now retries `EINTR` and requires the complete one-byte
payload from `sendmsg()`. An interrupted or short send is no longer accepted as
successful descriptor delivery and remains fail-visible to the scan caller.
Source/evidence controls pass; the disposable image lacks the libcurl/OpenSSL
development headers needed for a fresh on-access object.

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
Source/evidence controls pass; fresh object/runtime evidence remains blocked by
the disposable image's missing development headers.

Fresh current-source object verification then succeeded in a disposable ARM64
container after installing the missing development packages inside that
container: `clamonacc/client/protocol.c.o` and `common/clamdcom.c.o` both
compiled from the canonical checkout. The complete `clamonacc` link was not
claimed because Cargo attempted to refresh unavailable Git dependencies; this
is object-level development evidence, not certified x86-64 runtime evidence.

After adding Git to the disposable container, the complete current-source
`clamonacc` target built and linked at 100% with Clang 16.0.6 and Rust 1.97.1,
with UnRAR, Milter, fanotify, and shared libclamav enabled. The resulting
ARM64 development identities are:

- `clamonacc`: `b1fdaa8d73a29668c097577fd9ec163fa0d221e45aa519e96e7340ede109d8ef`
- `libclamav.so.14.0.0`: `a656c48e7ecb857291ea96fde13a08c1fa6c6b636e50a1cadece493ec8d1dfda`
- `libcommon.a`: `eaa517a32169a0c02f176802cddf65ca5157f34a392b0ba78a14776207db930c`
- `CMakeCache.txt`: `039a59ed62bb2a8f5ee9125d3e3a7b7380c4c33caac01421909634d677602915`

In a disposable runtime container with `-c /dev/null`, the freshly linked
`clamonacc --help` command exited 0 and reported
`ClamAV: On Access Scanning Application and Client 1.5.3-largefile-devel`.
This is current-source ARM64 development build/runtime evidence; it is not
certified x86-64, privileged fanotify, or full-size qualification evidence.

The rebuilt `check_clamd` client stream-accounting test case passed 10/10 in
the disposable ARM64 container, including the new regression that attaches a
regular file at descriptor 0, starts from a nonzero offset, and verifies that
the shared `zINSTREAM` sender rewinds and transmits the complete payload.
The same group retained its expected over-limit and descriptor-error checks.
This is focused development evidence; it does not replace certified
x86-64/full-size runtime qualification.

Shared `sendln()` now retries an interrupted `send()` when it returns `-1`
with `EINTR`; the former positive-result condition could turn a transient
signal into a false clamd transport failure. A deterministic socketpair test
fills the sender, interrupts the blocked call, drains the peer, and verifies
the payload completes. The rebuilt client stream-accounting group passed
11/11 in the disposable ARM64 container. This remains development evidence,
not certified x86-64/full-size qualification.

Follow-on Sonic1 repaired-source legacy-wire service slice (2026-09-09 UTC):

- The repaired `clamd` build was started from the isolated Sonic1 source/build
  graph recorded in the R03 receipt, with the validated unsigned CUD plus the
  canonical NDB detection signature. The service listened on an isolated
  loopback TCP port and was stopped after the checks.
- A direct standard-library probe received the exact NUL-terminated `PONG`
  reply for `zPING`, `/src/README.md: OK` for `zSCAN`, and
  `/src/unit_tests/clamscan/allmatch_test.py:
  NDB.Clamav-Unit-Test-Signature.UNOFFICIAL FOUND` for `zCONTSCAN`.
- The same probe exercised `zINSTREAM` with chunk framing and a terminating
  zero-length chunk. README returned `stream: OK`; the exact-detection fixture
  returned `stream: NDB.Clamav-Unit-Test-Signature.UNOFFICIAL FOUND`.
- The probe process exited `0`; the scan outcome was bound to the exact daemon
  reply text, not inferred from the probe process exit. These direct legacy
  records remain development ingress evidence and are intentionally not
  promoted into the R04 structured-record map because legacy replies do not
  carry the structured counters and native alert offsets required there.

This strengthens the repaired-source R10 path across daemon health, legacy
path scan, legacy detection, and stream ingress. It does not establish the
certified/full-size/sanitizer matrix, fd-passing, milter, privileged fanotify,
or production-canary requirements. No host software was installed, no usage
reset was used, and no commit, push, or GitHub workflow action was performed.

Follow-on Sonic1 sanitizer multiscan-stream slice (2026-09-09 UTC):

- The rebuilt sanitizer `clamdscan --help` confirmed that `--multiscan` and
  `--stream` are independently supported. `--multiscan` alone was first
  exercised against a client-only path and correctly returned exit `2` with
  `INCOMPLETE (Can't get file status)`; the daemon cannot stat a path that is
  not mounted in its container.
- The meaningful cross-container combination,
  `clamdscan --multiscan --stream`, then returned clean exit `0`/`OK` and
  detection exit `1` with the exact
  `LargeFile.POC.32g-edge.UNOFFICIAL FOUND` alert through the isolated
  sanitizer daemon. The daemon was stopped after the probes.
- The clean structured report is
  `/tmp/clamdscan-c-asan-ubsan-multiscan-stream-clean-20260909.jsonl`, hash
  `98de9afb1e38adc23d968c1216e800f812c5f8b0f217ae0437c24f160751a48a`;
  it records `COMPLETE`, `root_size=logical_bytes=1048576`, and
  `skipped_operations=0`. The detection report is
  `/tmp/clamdscan-c-asan-ubsan-multiscan-stream-detect-20260909.jsonl`, hash
  `d1bd2bb0f2685bc84d27c38d5ebabc6ef4b44c318e7f87b392577914a4a884f7`;
  it records `DETECTION_TERMINATED`, the exact alert, and
  `last_alert_offset=1048512`.

This adds development sanitizer evidence for the multiscan-plus-stream
combination. It remains non-qualifying until the complete current source graph,
certified candidate, full-size cases, and R04-bound records are available.

Plain multiscan path slice (2026-09-09 UTC):

- The same rebuilt sanitizer daemon was given the two fixture paths with the
  same read-only paths mounted in both the client and daemon containers. This
  exercised `clamdscan --multiscan` as a real path request rather than using a
  stream fallback.
- The clean request returned exit `0` and `OK`; the detected request returned
  exit `1` with `LargeFile.POC.32g-edge.UNOFFICIAL FOUND`. The clean report
  hash is `b0be52182846c58bb70de0ad702954b486a66e9c32e2508c20f604457c101e47`;
  it records `COMPLETE`, `root_size=logical_bytes=1048576`, and zero skipped
  operations. The detection report hash is
  `be9f3a34e4adfe70dfb6904b768b625a314967af97da1cbdb22724bbd7ac9c12`;
  it records `DETECTION_TERMINATED`, the exact alert, and
  `last_alert_offset=1048512`.
- The named sanitizer daemon was stopped after the probes. This is
  development evidence for plain multiscan path ingress, not certified or
  full-size qualification evidence.

Fdpass-plus-multiscan sanitizer slice (2026-09-09 UTC):

- The first disposable Unix-socket attempt stopped before application ingress
  because a fresh named socket volume was root-owned. The daemon reported
  `Permission denied` while binding the socket, and LeakSanitizer reported a
  2,313-byte engine-init leak on that startup-abort path. The volume was
  repaired in place and the probe was rerun; this finding led to a source
  cleanup change in `clamd/clamd.c`.
- With the disposable socket permissions corrected, `clamdscan --fdpass
  --multiscan` returned clean exit `0`/`OK` and detection exit `1` with the
  exact `LargeFile.POC.32g-edge.UNOFFICIAL FOUND` alert. The retained report
  hashes are `0ccdc70a032d8f905527e257236608e0c9ec5f066977a89794853f21e70a0795`
  (clean) and `47beae9900b9e287f3b07de794801f0b1a100eee3ab34eebff2a741339279f79`
  (detection); the detection report binds `DETECTION_TERMINATED` and
  `last_alert_offset=1048512`.
- The successful daemon log contained no ASan, UBSan, or LeakSanitizer
  diagnostic. The local source now clears the engine ownership transfer after
  `recvloop()` and frees the engine on startup failure before that transfer.
  The remote sanitizer binary predates this source correction, so a post-fix
  sanitizer startup rerun remains required before treating the leak as closed.

This adds development sanitizer evidence for fd-passing plus multiscan while
preserving the distinction between a fixed source path and a pre-fix remote
binary. It does not establish certified/full-size qualification.

Qualification-harness parity correction (2026-09-09 UTC):

- The service workload verifier now treats `clamdscan --multiscan`,
  `clamdscan --stream --multiscan`, and `clamdscan --fdpass --multiscan` as
  three distinct report-backed edge workloads. They are no longer implicitly
  covered by the direct legacy-wire `MULTISCAN` record.
- The service qualification script invokes all three combinations against the
  edge database and records each report independently. The synthetic evidence
  control and focused workload tests include the same required labels.

This closes a harness omission in the R10 matrix; it does not change any
capability status until a clean, immutable, full-size run produces the records.

Current-source C translation-unit check (2026-09-09 UTC):

- On Sonic1, after a bounded current-source overlay and successful CMake
  configure, the existing compiler built `common/clamdcom.c` with the generated
  project flags and no diagnostics. The same check built `clamd/clamd.c`,
  covering the paired startup cleanup used by the daemon ingress path.
- The same generated-flag check also built `clamdscan/client.c` with no
  diagnostics, covering the client-side path selection for default, fdpass,
  stream, and multiscan combinations.
- The full current-source application build remains blocked at the locked Rust
  dependency graph (`adler2 v2.0.1`, followed by
  `android_system_properties v0.1.5` in offline checks). These C-only results
  are development source evidence; they do not replace the required immutable
  full-size R10 service matrix and R04-bound reports.

Development producer record loop (2026-09-09 UTC):

- Inside the existing Docker runtime, the ARM64 Debug service build produced
  24 validated R04 records: clean, detection, and limit outcomes for the six
  structured daemon REPORT commands and for `clamdscan --fdpass` and
  `clamdscan --stream`.
- The retained evidence is under
  `/private/tmp/clamav-r04-service-capture-20260909`; the record file hash is
  `4b2d864b14916807c67c928766f7403ce7d35cbe19d91de93096b3ae4d6e2407`.
  The generic verifier accepted all 24 rows with exit 0 and no artifact or
  service-fixture identity mismatch.

This is a development ARM64/64 MiB envelope and does not qualify the R10
matrix. The separate multiscan combinations, full-size inputs, certified
current-source build, milter, and R04-bound full matrix remain required.

Development lifecycle evidence integration (2026-09-09 UTC):

- The development producer now records a per-outcome lifecycle artifact with
  pre/post daemon PING results, whether the daemon was running before stop,
  whether it exited, and whether its socket disappeared after cleanup.
- Every emitted development record binds that artifact and includes an explicit
  daemon-health/cleanup marker. Health or cleanup failure changes the record to
  fail rather than allowing a transport success to masquerade as a complete
  service case.
- The retained 24-record bundle above predates this producer change and still
  passes the generic validator; it is not being relabelled as lifecycle-complete
  evidence.
- This strengthens the development producer contract only; no R10 capability
  status changed and the certified/full-size service matrix remains open.

Release-service lifecycle contract (2026-09-09 UTC):

- The release qualification runner now retains a generation-tagged
  `provenance/service-lifecycle.tsv` record for every daemon start/stop cycle.
  Each generation requires an exact startup PONG, a final pre-stop PONG, a
  live daemon before stop, a reaped process after stop, and removal of both the
  Unix socket and PID file.
- The independent service-evidence verifier requires the lifecycle artifact,
  validates every generation's six-event contract, and rejects a tampered
  cleanup result. Its path and SHA-256 are also bound into the service build
  identity. The synthetic runtime evidence regression passed, and shell
  syntax/source guards passed.
- No real release service run was claimed because the coherent current-source
  application build remains unavailable; no capability status changed.
