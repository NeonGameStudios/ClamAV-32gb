# R13 Sonic1 current-candidate fanotify clean prevention — 2026-09-21

## Scope and provenance

This receipt records a fresh real Linux fanotify permission-path run against
the current packaged worktree. It proves the clean prevention path with the
repository test-signature database and a deterministic plain-text fixture. It
does not claim production-CVD coverage or final release readiness.

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
- Build: `/build` from the current package; runtime source mount `/src` was read-only.
- Database: `/build/fanotify-db-current-20260921/clean-control.ndb`.
- Database SHA-256: `4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`.
- Private tmpfs fixture mount: `/tmp/clamav-fanotify-current-clean`.
- Fixture SHA-256: `4080ea4c7f7e4301bf06d1f2a8d597d41dbca654b72a2d21fd4ec498ba6b14ec`.
- Runner output: `/build/fanotify-clean-current-20260921`.

## Result

MCP-SSH job `job_254db3aee7d34cf79aec7a42da146ca1` exited 0. The result was:

```json
{"case_name":"clean","completion":"COMPLETE","permission_response":"FAN_ALLOW","scan_exit_code":0}
```

The observer and clamonacc both recorded `FAN_ALLOW`; the non-root actor
opened the fixture. The scan report was complete, status 0, with parser and
detector operations. Startup PONG, pre-cleanup PONG, process shutdown, PID
cleanup, and socket cleanup all passed.

Configuration included `MaxFileSize 32G`, `MaxScanSize 64G`,
`MaxTemporarySize 64G`, `PCREMaxFileSize 32G`, `MaxMatcherWork 256G`, and
`MaxContiguousSize 32G`.

Retained artifact hashes:

- `result.json`: `21a566462ce765e46e33d90359e25baa3d0c968a9fec34253ffedb5d26c41484`
- `provenance.json`: `42a58c1828cb45cc6c6e43635c6b791de86f9adb6cbf9ee56af57b3da2befa91`
- `health-cleanup.json`: `7a7bf8d384358d8942e780caf9e93861e297ac2415fe508967c358ca5018a668`
- `bound/kernel-event.jsonl`: `6c5dafe408f6b59544094cccc7c8d37477e70308a9137ea903ead9eda2bcc01e`
- `bound/scan-report.jsonl`: `e264f51a913fe2ec24b42bddfbba5dd945ba4cb2f8617353709005e2745dab6d`
- `bound/actor-result.jsonl`: `b6db2f969d05db30ec24ec881b7d23fe4476c0a94a74f6282c2b34030ffe8517`
- `raw/clamonacc-permission.jsonl`: `87edc74fb4f22d791f9d241aeddd4c8cab647b248a936481254042d17b63c0f2`
- `raw/clamonacc-report.jsonl`: `8af88e93cb40d718f563e81c9d06aaed7eafbfabe654dad8489904496b3713aa`
- `clamd.conf`: `af4176f535d141cc94ef08ac86116df7de4c3c152a73abf964191462d2450aa5`

## Boundary

This is development verification only. No capability was promoted. Production
CVD, materialized 32-GiB, parser/deep-inspection, service, sanitizer, and
remaining resource/readiness gates remain open.

State: `development-verified; current-fanotify-clean-prevention-passed; release-gates-open`
