# R10 — Sonic1 current-source clamav-milter protocol

Date: 2026-09-19
Task ID / parent milestone: `R10` / milter ingress

## Evidence identity

- Branch: `largefile-roadmap-qualification`
- Source commit: `c6de97b9`
- Host: `sonic1`, login profile `sonic1-camera-key`
- Container: `clamav-current-7f3458c4`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Image: `clamav-32gb:dev-current`
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- `clamd`: `/tmp/clamav-7f3458c4-build/clamd/clamd`
- `clamav-milter`: `/tmp/clamav-7f3458c4-build/clamav-milter/clamav-milter`
- Certificate directory: `/src/unit_tests/input/signing/verify`

The container provenance reported the rebuilt source bind mounted at `/src`.

## Supported protocol test

The repository-supported test was run with its CTest-compatible development
limit mode:

```text
python3 milter_protocol_test.py
MILTER_DEVELOPMENT_LEGACY_LIMITS=1
```

The test exited `0` with no stderr and reported:

```text
milter protocol cases: {'clean': 'a', 'infected': 'r', 'exact_limit': 'a', 'limit_plus_one': 't'} (extra database: none)
```

These actions are the expected protocol results for clean acceptance, exact
malware rejection, exact-limit acceptance, and limit-plus-one termination.

## Boundary

This proves the current-source milter protocol control and bounded limit
behavior on Sonic1. It uses the fast development-limit fixture; it is not the
literal materialized 32-GiB milter wire case, R04 acceptance evidence, or
release qualification.

State: `development-verified`; qualification pending.
