# R13 Sonic1 current-candidate fanotify monitoring-only — 2026-09-21

## Scope and provenance

This receipt records a fresh real Linux monitoring-only run against the
current packaged worktree. It proves clean actor/report semantics without a
permission event and does not claim prevention, production-CVD coverage, or
final release readiness.

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
- Private tmpfs fixture mount: `/tmp/clamav-fanotify-current-monitor2`.
- Fixture SHA-256: `a6e0601d69c9d95a6771c2af2bcb9a90d7fce2e8d38c69ab46c86297a77be38b`.
- Runner output: `/build/fanotify-monitor-current-20260921-retry`.

## Result

MCP-SSH job `job_159d7174433a4d01a92e6abc1bc28648` exited 0. The result was:

```json
{"case_name":"clean","mode":"monitoring-only","actor":"raw/monitor-actor.json","report":"raw/clamonacc-report.jsonl"}
```

The non-root actor opened the fixture. The report was complete, status 0,
`No viruses detected`, with parser and detector operations and
`clamonacc_event_id=0`; the permission-decision artifact was empty as required
for monitoring-only mode. Startup and cleanup health passed, and clamd,
clamonacc, and the actor exited cleanly with PID/socket cleanup complete.

Retained artifact hashes:

- `result.json`: `438e7de2a2afedda83a8e52e45bb46928c504fb617d948a60cdab41b48a15808`
- `provenance.json`: `d7ddc29c887ba7612fc4a89cd1ccbbd4802cffccf1c313628b3a4d52b37715de`
- `health-cleanup.json`: `84dafdf83c7d555e7c41929173dbc98b151a1986d76e4b20f9e764e0de0b8ddc`
- `raw/monitor-actor.json`: `d412ec29f1c06ced92320b97a148b169ce85045e6336a1ccf45b089125f5e839`
- `raw/clamonacc-report.jsonl`: `f24bf2f8849d6ddae31d9640c639fd7d43ea096126b0bda9d8c25ef278c782f6`
- `clamd.conf`: `0be32b1f266972f6c60593e9bbc24b052e3df1f80e8c31a5b09ca5c350ac6849`

## Boundary

This is development verification only. It does not promote a capability and
does not alter the requirements for prevention, production CVDs, materialized
32-GiB scans, service canaries, sanitizer coverage, or final readiness.

State: `development-verified; current-fanotify-monitoring-only-passed; release-gates-open`
