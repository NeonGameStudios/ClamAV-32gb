# R10 — Sonic1 native milter controls

Date: 2026-09-19
Task ID / parent milestone: `R10` / milter controls

## Evidence identity

- Branch: `largefile-roadmap-qualification`
- Source commit: `c6de97b9`
- Host: `sonic1`, login profile `sonic1-camera-key`
- Container: `clamav-current-7f3458c4`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Image: `clamav-32gb:dev-current`
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`

The container provenance reported the rebuilt source bind mounted at `/src`.

## Native controls

The current build ran each registered native control with no source or image
mutation:

```text
/tmp/clamav-7f3458c4-build/unit_tests/check_clamfi_quota
exit: 0

/tmp/clamav-7f3458c4-build/unit_tests/check_milter_skipauth
exit: 0
stderr: ERROR: Failed to compile regex '[' in allow list file

/tmp/clamav-7f3458c4-build/unit_tests/check_milter_connpool
exit: 0
duration: 61 seconds
```

The malformed allow-list regex diagnostic is the expected negative-path case
for the skip-auth control. The connection-pool stress control was run as a
tracked asynchronous job because it exceeds the synchronous helper’s 20-second
ceiling; it completed with exit `0`.

## Boundary

This records native quota arithmetic, skip-auth validation, and connection-pool
stress coverage for the current milter build. It is supporting R10 ingress
evidence, not a literal materialized 32-GiB milter transfer, R04 acceptance
evidence, or release qualification.

State: `development-verified`; qualification pending.
