# R13 Sonic1 privileged fanotify clean prevention slice — 2026-09-21

## Scope and provenance

This receipt records a real Linux fanotify permission-path run for the current
candidate. It proves the clean prevention path with a repository test
signature database and a plain-text fixture. It does not claim production-CVD,
malware-denial, incomplete/resource-denial, or final release readiness.

- Branch: `largefile-roadmap-qualification`.
- Candidate commit: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`.
- Source archive SHA-256: `599c78070d0b745f23dc30476f3c564e68a0f1f8a35ae403ca18c95a95ef5f84`.
- Durable transfer: `transfer_22f567da4bad4db498156976272bf859`.
- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `5ce5ee02ec1cc4988d2e1338dc48bdb711e4bfdb26cf147beaa6a0efc6efd69b`.
- Image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Privileged container capabilities: root-equivalent with fanotify mount access.
- Build: `/build/release-clean-5798545b`.
- Database: `/build/fanotify-db-20260921/clean-control.ndb`, copied from
  `unit_tests/input/other_sigs/Clamav-Unit-Test-Signature.ndb`.
- Private bind mount: `/tmp/clamav-fanotify-mount-20260921-clean`.
- Runner output: `/build/fanotify-clean-20260921-ndb3`.

The source and build mounts were immutable for the runner. The disposable
mount was private to the test container and the runner retained provenance,
raw kernel event, actor, report, health, and cleanup artifacts.

## Result

MCP-SSH job `job_5e33ae82edc149e6815d4a68a2ef7cdc` exited 0. The bound result
was:

```json
{"case_name":"clean","completion":"COMPLETE","permission_response":"FAN_ALLOW","scan_exit_code":0}
```

The raw event was `FAN_OPEN_PERM` with observer and clamonacc responses both
`FAN_ALLOW`; the non-root actor (UID 65534) opened the fixture successfully.
The clamd report recorded `No viruses detected`, status 0, `COMPLETE`, zero
skipped operations, and a pre-cleanup PONG. Cleanup was complete: observer,
clamonacc, and clamd exited 0, and both PID and socket artifacts were absent.

The fixture was the 92-byte plain-text test-signature file with SHA-256
`4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`.
The run used `CVDCertsDirectory /src/certs` so database initialization was
explicit and deterministic; no production CVD was used.

Retained artifact hashes:

- `result.json`: `526ee961774fcecb7f56e8476b03b6fe06546e53e77bf2e2a230105f3f563a9b`
- `provenance.json`: `a4fe07e70185d6eee555236ed233a68fab8cfd918e4c5ff2ed2ba85614a1750c`
- `health-cleanup.json`: `7a7bf8d384358d8942e780caf9e93861e297ac2415fe508967c358ca5018a668`
- `bound/kernel-event.jsonl`: `c1b07f06a77ea93c55ef2d77cee2e2f57b55575eda1f46d6c625187203eb1b4b`
- `bound/actor-result.jsonl`: `67b87f623988b6bb941632ad279bea83fc10263c9bc7132f7b714ace519f1bc4`
- `bound/scan-report.jsonl`: `983fa5c187f7ef002eab042d643d9a6ec8b981f3cb87975d690818786ac7bd7c`
- `clamd.conf`: `c2bd50b5795160bb46c5eb1ef596c25554372ef5ce278040cc6f5a4eb313793e`

## Boundary

This closes only the R13 clean permission-allow slice. The CVD attempts that
preceded it failed visibly because the dated synthetic CVD corpus was not
trusted by the supplied certificate chain; those failures were retained
separately and were not converted into passing evidence. Production CVD
canary coverage, malware and incomplete/resource/timeout/parser denial cases,
and final capability-specific readiness remain open.

State: `development-verified; fanotify-clean-prevention-passed; production-cvd-and-denial-gates-open`
