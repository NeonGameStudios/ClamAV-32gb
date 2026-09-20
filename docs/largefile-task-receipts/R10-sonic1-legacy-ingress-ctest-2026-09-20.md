# Task receipt: R10 Sonic1 legacy ingress CTest

Task ID / parent milestone: `R10` / `R03`

Scope: run the current-source `clamscan` and `clamd` CTest targets after the
structured-report service matrix. These are bounded unit/corpus controls; the
run does not claim full-size materialized ingress, sanitizer parity, production
CVD behavior, milter exact-edge qualification, or release readiness.

Environment and identity:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Source bind: `/tmp/clamav-32gb-current-20260915` mounted at `/src`.
- Build directory: `/src/build-roadmap-20260920`.

Command and result:

```text
ctest --test-dir /src/build-roadmap-20260920 --output-on-failure -R '^(clamd|clamscan)$'
exit=0

1/2 Test #25: clamscan ......................... Passed 24.60 sec
2/2 Test #26: clamd ............................ Passed 35.80 sec
100% tests passed, 0 tests failed out of 2
Total Test time (real) = 60.40 sec
```

The production-linked `clamd` test covers the legacy non-report command family
including `SCAN`, `CONTSCAN`, `MULTISCAN`, `FILDES`, and `INSTREAM`, alongside
protocol rejection and detection/clean controls. The `clamscan` target covers
the current CLI corpus and admission controls in the same coherent build.

Retained output:

- `/tmp/clamav-r10-sonic1-legacy-ctest-20260920.log`
- SHA-256:
  `249c1f5d9d2a12df16d0fd55c439a9db94cac013f6f3a61cd277ab53e65d545f`

Remaining work: capability-specific R04 records for these legacy ingress rows,
full-size exact/materialized cases, milter and on-access runtime evidence,
sanitizer/production-CVD parity, resource and fanotify proof, and final release
readiness remain open.

State: `development-verified; full-size-and-release-evidence-open`
