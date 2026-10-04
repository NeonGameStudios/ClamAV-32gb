# R13 Sonic1 fanotify monitoring-only clean slice — 2026-09-21

## Scope and provenance

This receipt records the separate monitoring-only semantics case for the
current candidate. It proves that a clean non-root actor is allowed and that
the monitoring-only path retains a complete scan report without a permission
event. It does not claim prevention, production-CVD, or final release
readiness.

- Branch: `largefile-roadmap-qualification`.
- Candidate commit: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`.
- Source archive SHA-256: `599c78070d0b745f23dc30476f3c564e68a0f1f8a35ae403ca18c95a95ef5f84`.
- Durable transfer: `transfer_22f567da4bad4db498156976272bf859`.
- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `8084bf926b348d1418e688a1682ae4ca2e8db8094a58d1d062171e1a3d3682e4`.
- Image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Build: `/build/release-clean-5798545b`.
- Database: `/build/fanotify-db-20260921/clean-control.ndb`.
- Private bind mount: `/tmp/clamav-fanotify-mount-20260921-clean`.
- Runner output: `/build/fanotify-monitor-20260921`.
- Fixture SHA-256: `4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`.

## Result

MCP-SSH job `job_2c8f617b3e0b418f9e3e231afddd96a4` exited 0. The runner
returned `mode=monitoring-only` with actor and report artifacts. The actor
(UID 65534) opened the fixture successfully; the report was `COMPLETE`, status
0, `No viruses detected`, zero skipped operations, and `clamonacc_event_id=0`
as required for monitoring-only evidence. Startup and pre-cleanup PONGs
succeeded, and clamd, clamonacc, and the actor all exited 0 with PID/socket
cleanup complete.

Retained artifact hashes:

- `result.json`: `ed5ac88351448a528bf91470ee61cd927d38ad65b850439fb79e04bb5c70ac54`
- `provenance.json`: `e6f1e6ee7bf8d02ff8a98cf4dd9c0eaacfb70c463a2ed67f42a51f9403f6dcb2`
- `health-cleanup.json`: `84dafdf83c7d555e7c41929173dbc98b151a1986d76e4b20f9e764e0de0b8ddc`
- `raw/monitor-actor.json`: `d412ec29f1c06ced92320b97a148b169ce85045e6336a1ccf45b089125f5e839`
- `raw/clamonacc-report.jsonl`: `56407b9df175c06fad3c673379dca182b1c755613af505ee0c2200bbc79bb27c`
- `clamd.conf`: `b250f017e687f5ede1869327ed8a8e6aa390304e638f2b9b0624468a09e04434`

## Boundary

This closes the monitoring-only semantics slice on the current candidate. It
does not promote any capability and does not alter the separate requirement
for authorized production CVDs, full-size service canaries, and final
readiness.

State: `development-verified; fanotify-monitoring-only-passed; production-cvd-and-release-gates-open`
