# Task receipt: R10 native-temp daemon revalidation

Task ID / parent milestone: `R10` / `R00`

Scope: revalidate the current-source daemon and report-client changes after
the structured-report malformed-alert fix. This is ARM64 development evidence,
not certified release qualification.

Starting identity:

- Canonical source: `<repository-root>`.
- Branch: `largefile-roadmap-qualification`.
- Rebuilt static/debug artifacts: `/private/tmp/clamav-largefile-static-build`.
- Build and runtime dependencies were installed only inside disposable Docker
  containers; no host installation was performed.

Observed environment control:

- CTest's daemon target cannot use the host-mounted build directory for its
  Unix socket: clamd reports `Operation not supported` while binding or
  chmod'ing `clamd-test.socket`.
- Running the same current-source Python integration suite with `TMP` on the
  container-native filesystem removes that mount-specific failure mode.

Commands and results:

- `CK_DEFAULT_TIMEOUT=300 CK_RUN_SUITE=cl_suite CK_RUN_CASE=mhtml check_clamav`
  — 5/5 checks passed.
- `CK_DEFAULT_TIMEOUT=300 CK_RUN_SUITE=cl_suite check_clamav` — 2,271/2,271
  checks passed.
- Native-temp current-source `python3 -m unittest --verbose clamd_test.py`
  with the rebuilt `clamd`, `clamdscan`, and `check_clamd` paths — 15/15 tests
  passed.
- `clamav_milter_quota` — 2/2 checks passed.
- Focused `check_clamd` report/client group — 27/27 checks passed, including
  exact-name detection and rejection of infected structured reports without a
  nonempty `last_alert`.

Changes verified:

- `CONTSCANREPORT`, `MULTISCANREPORT`, and `ALLMATCHSCANREPORT` now treat the
  zero return from `sendln()` as success and read the resulting frame.
- Human-readable infected output is emitted only when the structured report
  supplies a nonempty exact alert name; a bare `FOUND` line is not substituted.
- The same fail-closed rule is applied to the parallel report-client path.

Full-size/certified evidence produced, or explicitly not run: no Linux x86-64
Release/sanitizer evidence, certified 32-GiB service run, production CVD,
fanotify evidence, or R04 acceptance record was produced.

Remaining failures / next slice: retain these records on the authorized
Linux x86-64 runner, then exercise the R04-bound known-size/unknown-size
ingress cases and the full-size service oversize probe.

State: `development-verified`; release readiness remains blocked.
