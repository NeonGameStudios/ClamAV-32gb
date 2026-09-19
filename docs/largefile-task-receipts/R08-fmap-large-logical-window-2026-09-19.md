# R08 — 32-GiB logical fmap window traversal

Date: 2026-09-19
Task ID / parent milestone: `R08` / common fmap and reader behavior

## Scope

Exercise the complete 32-GiB logical coordinate range through the callback-
backed `cl_fmap` path. The test uses 64-KiB windows and synthesizes distinct
page content, so it checks high offsets and refills without allocating a
32-GiB file or using the missing disk space required by the exact-materialized
qualification case.

No capability row is promoted to qualified by this receipt.

## Evidence identity

- Branch: `largefile-roadmap-qualification`
- Source commit: `4391c257`
- Host: `sonic1`, login profile `sonic1-camera-key`
- Container: `clamav-current-7f3458c4`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Image: `clamav-32gb:dev-current`
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Binary: `/tmp/clamav-7f3458c4-build/unit_tests/check_clamav`

The container provenance reported `/src` bound read/write from
`/tmp/clamav-32gb-7f3458c4`. The binary was rebuilt from the current source
before this run.

## Command and result

```text
docker exec -u 0 -w /src \
  -e CVD_CERTS_DIR=/src/unit_tests/input/signing/verify \
  -e CK_RUN_SUITE=cl_suite \
  -e CK_RUN_CASE=fmap_large_logical \
  -e CLAMAV_FMAP_REGRESSION=1 \
  -e T=1200 \
  clamav-current-7f3458c4 \
  /tmp/clamav-7f3458c4-build/unit_tests/check_clamav

Running suite(s): cl_suite
100%: Checks: 1, Failures: 0, Errors: 0
exit: 0
stderr: empty
```

## Boundary

This validates logical high-offset fmap traversal and bounded callback-backed
residency only. The fully allocated exact-32-GiB tail-detection test remains
pending because Sonic1 currently has approximately 57 GB free on the active
filesystem while the roadmap admission requirement is at least 68 GiB of
disk-backed temporary space. Certified x86-64, sanitizer, production-service,
R04 acceptance, and final release evidence remain open.

State: `development-verified`; qualification pending.
