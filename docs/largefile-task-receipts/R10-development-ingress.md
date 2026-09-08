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
