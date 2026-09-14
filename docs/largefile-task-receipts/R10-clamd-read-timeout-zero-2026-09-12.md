# Task receipt: R10 clamd `ReadTimeout=0` stream semantics

Task ID / parent milestone: `R10`.

Exact capability under review: `clamd:INSTREAM`.

This receipt records a focused ARM64 development verification. It does not
promote the capability or replace the certified Linux x86-64 qualification
run.

## Source and build identity

- Canonical checkout: `<repository-root>`.
- Branch: `largefile-roadmap-qualification`.
- Base HEAD: `8e837b88c89874b180a1a25f22d287f7d6be29db`.
- Current dirty-source manifest SHA-256:
  `064540666ce4a83742c68e5e0aedcf5f1673e41b6019f305841de64470ebf499`.
- Rebuilt ARM64 Release `clamd` SHA-256:
  `7385bb19f2a362b050fd7746d54881c61de496e7f62807b94b80a8c0d1d3043e`.
- The existing dirty working tree was preserved. No reset, clean, commit,
  push, deployment, GitHub workflow action, host package installation, or
  usage-reset action was performed.

## Observed gap and change

`ReadTimeout=0` is the documented no-deadline setting, but the stream command
path unconditionally set `timeout_at` to the current time plus zero. A client
that sent a valid `INSTREAM` header and then paused for data could therefore
be rejected immediately instead of waiting indefinitely.

- Added one timeout helper that preserves the zero sentinel when
  `ReadTimeout=0` and applies a deadline only for positive values.
- Applied the helper to both command parsing and stream handling, while
  retaining the existing admission deadline behavior.
- Added a Unix clamd integration test that sends a one-byte chunk, waits past
  the normal test socket timeout, and then completes the stream; it asserts
  that the daemon waits and returns `stream: OK`.
- Corrected the test helper so a caller-supplied clamd configuration is used,
  making the custom `ReadTimeout 0` fixture effective.
- Documented the zero-value behavior in both sample configurations, the
  generated man-page source, and the capability manifest.

## Development verification

- Current-source ARM64 Release clamd test: `clamd` 1/1 passed in 32.50
  seconds. The retained test log reports 17 Python tests, including
  `test_clamd_read_timeout_zero_waits_for_stream_data` and
  `test_clamd_read_timeout_zero_waits_for_stream_report_data`, with `OK`.
- Host-side `sh tools/largefile_source_guards.sh`: passed, including the
  597-entry capability manifest, release-readiness checks, acceptance schemas,
  and legacy clamd protocol checks.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md`: passed.
- `git diff --check`: passed.
- Current-source ARM64 Release CTest excluding the separately run `clamd` and
  `largefile_source_guards` tests: 14/14 passed in 130.10 seconds, covering
  libclamav, Rust, clamscan, freshclam, sigtool, milter, and the large-file
  control/evidence tests. Combined with the dedicated `clamd` 1/1 result and
  the host-side source-guard result above, all 16 registered CTest targets are
  covered by current-source verification, though not by one resource-limited
  invocation.
- A subsequent full ARM64 CTest attempt passed `libclamav` and
  `largefile_poc_fail_closed`, then was killed with exit 137 while starting
  `largefile_source_guards` in the resource-constrained container. It is not
  counted as a complete matrix pass; the focused clamd result and host-side
  source-guard result above are the valid evidence recorded here.

The release-readiness status remains intentionally blocked: 597 total rows,
0 qualified, 143 bounded, 440 pending, 14 allowlisted unsupported, and 583
release blockers. This focused fix is development evidence only; certified
x86-64, sanitizer, production-CVD/service, full-size, Sonic1, resource, and
R04 qualification evidence remain open. No capability was promoted.

State: `development-verified`; release qualification remains pending.
