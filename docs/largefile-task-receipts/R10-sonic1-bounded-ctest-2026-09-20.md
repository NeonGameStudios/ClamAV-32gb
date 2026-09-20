# Task receipt: R10 Sonic1 bounded CTest controls

Task ID / parent milestone: `R10` / `R03`

Scope: run the current-source bounded CTest controls that exercise daemon,
on-access and milter pool behavior, evidence/schema producers, clamd report
protocol handling, and late-member controls. Full-size `libclamav`, exact-edge
milter, production-CVD, sanitizer and release workloads were deliberately not
included; this receipt does not promote a capability.

Environment and identity:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Source bind: `/tmp/clamav-32gb-current-20260915` mounted at `/src`.
- Build directory: `/src/build-roadmap-20260920`.

Command and result:

```text
ctest --test-dir /src/build-roadmap-20260920 --output-on-failure -R \
  '^(largefile_onaccess_threadpool|largefile_onaccess_config_admission|largefile_clamd_threadpool|largefile_milter_connpool|largefile_poc_fail_closed|largefile_runtime_evidence_check|largefile_service_evidence_check|largefile_acceptance_case_schema|largefile_acceptance_case_resources|largefile_acceptance_resource_capture|largefile_acceptance_case_producer|largefile_runtime_acceptance_case_producer|largefile_development_acceptance_capture|largefile_clamscan_admission|largefile_clamd_report_protocol|largefile_zip_late_member|clamav_milter_quota)$'
exit=0
17/17 passed
100% tests passed, 0 tests failed
Total Test time = 261.64 seconds
```

Covered controls:

- on-access thread-pool and configuration admission;
- clamd and milter connection-pool behavior;
- fail-closed PoC, runtime/service evidence verifiers and acceptance schema,
  resource capture and producer contracts;
- development acceptance capture, clamscan admission and clamd report
  protocol framing;
- ZIP late-member behavior and milter quota arithmetic.

The slowest selected control was the development acceptance capture at 240.54
seconds because it hashes the retained 32-GiB fixture as part of its source
identity contract. The exact output is retained on Sonic1 at
`/tmp/clamav-r10-sonic1-ctest-20260920.log` with SHA-256
`76553307430cb3bae05168e60d618e46ca5475713eb19970c6d8a856b4abd854`.

Remaining work: full-size certified ingress, milter and materialized-edge
evidence, sanitizer parity, real fanotify permission events, production CVDs,
and final release readiness remain open.

State: `development-verified; full-size-and-release-evidence-open`
