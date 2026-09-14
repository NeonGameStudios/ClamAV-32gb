# Task receipt: R10 development service revalidation — 2026-09-13

Task ID / parent milestone: `R10` / `R11`.

## Scope

Run the repository's current-source development service capture against the
preserved application build. Exercise the six structured `clamd` commands and
the six `clamdscan` client modes with clean, detection, and configured-limit
fixtures.

## Evidence

Runner: existing `clamav-current-rust-build-20260911` container, image
`rust:1.97-bookworm`, source mounted at `/src`, build directory
`/tmp/clamav-asan-current-20260912`.

Command:

```text
python3 /src/tools/largefile_development_service_capture.py \
  /tmp/clamav-asan-current-20260912/clamd/clamd \
  /tmp/clamav-r04-service-smoke-20260913 \
  --clamdscan /tmp/clamav-asan-current-20260912/clamdscan/clamdscan \
  --build-dir /tmp/clamav-asan-current-20260912
```

The capture exited `0` and wrote `36` R04 records. The direct structured
protocol cases covered `SCANREPORT`, `CONTSCANREPORT`, `MULTISCANREPORT`,
`ALLMATCHSCANREPORT`, `FILDESREPORT`, and `INSTREAMREPORT`. The client cases
covered `default`, `fdpass`, `stream`, `multiscan`, `stream-multiscan`, and
`fdpass-multiscan`. The record outcomes were 12 `COMPLETE`, 12
`DETECTION_TERMINATED`, and 12 `LIMIT_INCOMPLETE`, with each outcome matching
its expected exit code and report contract.

For clean, detection, and limit daemon instances, the lifecycle artifacts all
recorded successful pre/post PING health, a present PID file after startup,
normal daemon exit, and removal of both the socket and PID file during
cleanup. The capture's acceptance-record validation also passed.

## Qualification boundary

This is current-source ARM64 development service evidence using small private
fixtures and a sanitizer build. It does not prove exact 32-GiB/materialized
service behavior, production CVD coverage, certified Linux x86-64 resource
limits, milter, privileged fanotify, Sonic1, or final release readiness.

No software was installed, no usage reset was used, and no GitHub workflow,
commit, or push was performed.

State: `development-service-verified; full-service-qualification-open`.
