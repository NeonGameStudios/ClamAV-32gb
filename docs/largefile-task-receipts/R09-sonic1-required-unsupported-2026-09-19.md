# R09 — Sonic1 current-source required-unsupported regression

Date: 2026-09-19
Task ID / parent milestone: `R09` / `R03`

## Scope

Re-run the complete linked `required_unsupported` Check case against the
rebuilt current-source binary. The group covers the seven R09 rows that remain
in scope rather than treating them as deliberate exclusions:

- `matcher:rust-fuzzy-image-ffi-admission`
- `matcher:fuzzy-image`
- `parser:CL_TYPE_AI_MODEL`
- `parser:CL_TYPE_IGNORED`
- `parser:CL_TYPE_PYTHON_COMPILED`
- `parser:CL_TYPE_RAR`
- `parser:CL_TYPE_RARSFX`

No capability row is promoted to qualified by this receipt.

## Evidence identity

- Branch: `largefile-roadmap-qualification`
- Local source commit before this evidence receipt: `7c962b07`
- Host: `sonic1`, login profile `sonic1-camera-key`
- Container: `clamav-current-7f3458c4`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Image: `clamav-32gb:dev-current`
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Binary: `/tmp/clamav-7f3458c4-build/unit_tests/check_clamav`

The container provenance reported a running container with `/src` bound
read/write from `/tmp/clamav-32gb-7f3458c4`. The preceding build completed the
`check_clamav` target at 100% after the mail HTML normalization fix.

## Command and result

```text
docker exec -u 0 -w /src \
  -e CVD_CERTS_DIR=/src/unit_tests/input/signing/verify \
  -e CK_RUN_SUITE=cl_suite \
  -e CK_RUN_CASE=required_unsupported \
  -e T=1200 \
  clamav-current-7f3458c4 \
  /tmp/clamav-7f3458c4-build/unit_tests/check_clamav

Running suite(s): cl_suite
100%: Checks: 61, Failures: 0, Errors: 0
exit: 0
stderr: empty
```

## Boundary

This is current-container development evidence, not certified Linux x86-64,
sanitizer, production-CVD/service, materialized-large-file, R04 acceptance,
or final release evidence. Optional UnRAR extraction qualification and the
capability-specific full-size/runtime matrix remain open.

State: `development-verified`; qualification pending.
