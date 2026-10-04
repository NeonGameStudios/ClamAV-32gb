# R13 Sonic1 privileged fanotify exact-plus-one limit slice — 2026-09-21

## Scope and provenance

This receipt records the real Linux fanotify admission-limit case for the
current candidate. The input is sparse and tests metadata admission at exactly
32 GiB plus one byte; it intentionally does not claim a materialized
32-GiB scan, production-CVD coverage, or final release readiness.

- Branch: `largefile-roadmap-qualification`.
- Candidate commit: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`.
- Source archive SHA-256: `599c78070d0b745f23dc30476f3c564e68a0f1f8a35ae403ca18c95a95ef5f84`.
- Durable transfer: `transfer_22f567da4bad4db498156976272bf859`.
- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `3a415497d860e82c28e34a8213b5fcee082c1074c9b9aece34962c2ac91bf77f`.
- Image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Build: `/build/release-clean-5798545b`.
- Database: `/build/fanotify-db-20260921/clean-control.ndb`.
- Private bind mount: `/tmp/clamav-fanotify-mount-20260921-clean`.
- Runner output: `/build/fanotify-limit-20260921`.

The sparse fixture has logical size `34,359,738,369` bytes and SHA-256
`f631e197f98aceaefae8e587eb473e3173d81236fb99789e055908cb0d1b6ff8`.

## Result

MCP-SSH job `job_4c0771461ed94a62af8407c69bdf8cd4` exited 0. The bound result
was:

```json
{"case_name":"limit","completion":"LIMIT_INCOMPLETE","permission_response":"FAN_DENY","scan_exit_code":2}
```

The raw event was `FAN_OPEN_PERM`; clamonacc returned `FAN_DENY`, and the
non-root actor (UID 65534) failed to open the file with errno 1. The report
recorded `root_size=34359738369`, `Exceeded max scan size`, status 24,
`LIMIT_INCOMPLETE`, and one skipped operation before parser/matcher work.
Health and cleanup were complete: startup and pre-cleanup PONG succeeded,
all processes exited 0, and PID/socket artifacts were absent.

Retained artifact hashes:

- `result.json`: `ec345dd8673beb13304335ba7279936f934ec1a1ffe6a108001987a99a6e3006`
- `provenance.json`: `a86997bed4da87872610cdf6b15e7fd886e1a08f98f148f6200dfc871c7ce1b8`
- `health-cleanup.json`: `7a7bf8d384358d8942e780caf9e93861e297ac2415fe508967c358ca5018a668`
- `bound/kernel-event.jsonl`: `792dfc3a4e8c347ee40d7bba6dd63d44a62d3bc6f334a5a700c3b5604731a852`
- `bound/actor-result.jsonl`: `7f79a0dc127f2e3de88022d3571bb1bfe217191d92ffaef34037b48eda156280`
- `bound/scan-report.jsonl`: `a822f32d569b85003fe44d39ec25f46c10fd02db6aa6371fb218b478c4e108c5`
- `clamd.conf`: `f7c1a9acfd1b9a32d3604a9133e4f432a151331d73d418d9cab3ee6e0322d286`

## Boundary

This closes the R13 sparse exact-plus-one admission-deny slice. It does not
replace the fully materialized exact-edge qualification already recorded for
the library, nor the required incomplete/resource/timeout/parser denial cases
or production-CVD canary. No capability was promoted and final readiness
remains blocked.

State: `development-verified; fanotify-clean-detection-limit-passed; remaining-denial-and-production-cvd-gates-open`
