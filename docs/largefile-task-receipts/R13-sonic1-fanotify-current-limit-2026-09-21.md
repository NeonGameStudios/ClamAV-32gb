# R13 Sonic1 current-candidate fanotify exact-plus-one limit denial — 2026-09-21

## Scope and provenance

This receipt records a fresh real Linux fanotify admission-limit run against
the current packaged worktree. The input is sparse and tests logical size at
32 GiB plus one byte; it is not a materialized 32-GiB scan.

- Branch: `largefile-roadmap-qualification`.
- Candidate commit: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`.
- Source tree status at package time: dirty (package includes the exact worktree).
- Source package SHA-256: `17bffd2e101dc778edfc152b2373bfb12f619940484dc47e089be8038a1f075f`.
- Source manifest SHA-256: `7bbf88fcd56437380c9bce9852d89bf9a7a4c4603171eb444c76ef5f109bdde5`.
- Build identity SHA-256: `a481befbe2dc62af8ecc79f56337120db78608a4e95a1b5014e8c31c8d8d389e`.
- Host/profile: `sonic1` / `sonic1-camera-key`.
- Build container: `1d8c59cd38a87b49351af0a9a90bb6f4a4c740d5b0123f777f8151a71cf91859`.
- Runtime container: `c482bc8d2195e7db6d4a275042775e6c528270775f533f4ccf523df53ee8e13b`.
- Image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Database SHA-256: `4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`.
- Logical fixture size: `34,359,738,369` bytes.
- Fixture SHA-256: `f631e197f98aceaefae8e587eb473e3173d81236fb99789e055908cb0d1b6ff8`.
- Runner output: `/build/fanotify-limit-current-20260921`.

## Result

MCP-SSH job `job_485f72a966b245f6b4ba3716e440470a` exited 0. The result was:

```json
{"case_name":"limit","completion":"LIMIT_INCOMPLETE","permission_response":"FAN_DENY","scan_exit_code":2}
```

The report recorded root size `34359738369`, status 24, `LIMIT_INCOMPLETE`,
one skipped operation, and a `FAN_DENY` response. Startup, PONG, process
shutdown, PID cleanup, and socket cleanup passed.

Retained artifact hashes:

- `result.json`: `ec345dd8673beb13304335ba7279936f934ec1a1ffe6a108001987a99a6e3006`
- `provenance.json`: `c5245e04667503bf052317caa5115e3870d133863261bdb539d1fd3a0be6c584`
- `health-cleanup.json`: `7a7bf8d384358d8942e780caf9e93861e297ac2415fe508967c358ca5018a668`
- `raw/clamonacc-permission.jsonl`: `cebd66e3d7a6729ea031dba739ca4211ef390e71b276b48eb4566c434e775540`
- `raw/clamonacc-report.jsonl`: `196ef13c3e0b2b4cf78c11199399bd48bb3a4c54e3246e1528e1b1dff5ab1c3e`
- `clamd.conf`: `31c61b4cd5d373a6e05d82c2f5df08fb9eb6d601a1d70b78527bacbe18458138`

## Boundary

This closes only the sparse exact-plus-one admission-deny slice. It does not
replace materialized exact-edge qualification, production CVD coverage, or
the remaining resource/timeout/parser/service/sanitizer/readiness gates. No
capability was promoted.

State: `development-verified; current-fanotify-limit-deny-passed; release-gates-open`
