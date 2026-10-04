# R13 Sonic1 privileged fanotify detection-deny slice — 2026-09-21

## Scope and provenance

This receipt records a real Linux fanotify permission-path detection case for
the current candidate. It complements the clean allow receipt and does not
claim production-CVD, incomplete/resource/timeout/parser denial, or final
release readiness.

- Branch: `largefile-roadmap-qualification`.
- Candidate commit: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`.
- Source archive SHA-256: `599c78070d0b745f23dc30476f3c564e68a0f1f8a35ae403ca18c95a95ef5f84`.
- Durable transfer: `transfer_22f567da4bad4db498156976272bf859`.
- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `ef98aa680b8e6d4d261037cc76358d12de844e160abfdb5301347c171eb201ef`.
- Image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Build: `/build/release-clean-5798545b`.
- Database: `/build/fanotify-db-20260921/clean-control.ndb`.
- Private bind mount: `/tmp/clamav-fanotify-mount-20260921-clean`.
- Runner output: `/build/fanotify-detection-20260921`.

The actor fixture was the deterministic 28-byte string
`CLAMAV-TEST-STRING-NOT-EICAR`, matched at offset 0 by the repository NDB
signature. Its SHA-256 is
`e529e808342de154e3788b12554b23b6bfa1ca0af604e35b00ab51d0dc126f04`.

## Result

MCP-SSH job `job_6f9cb8a695b14cd98758439f6f4a9c5b` exited 0. The bound result
was:

```json
{"case_name":"detection","completion":"DETECTION_TERMINATED","permission_response":"FAN_DENY","scan_exit_code":1}
```

The raw event was `FAN_OPEN_PERM`; clamonacc returned `FAN_DENY`, the
non-root actor (UID 65534) failed to open the file with errno 1, and the report
contained `Virus(es) detected` with alert
`NDB.Clamav-Unit-Test-Signature.UNOFFICIAL` at offset 0. The report was
non-cacheable detection termination with zero skipped operations. Health and
cleanup were complete: clamd and clamonacc were alive before the actor,
pre-cleanup PONG succeeded, all processes exited 0, and PID/socket artifacts
were absent.

Retained artifact hashes:

- `result.json`: `432d5726cc8007036c582cb43f070efecc759083e47a3250fde0a884cddfb06e`
- `provenance.json`: `0f750dd4c8fc286aad2871608e6a933b009ad4efcc48e7029016031ad323411a`
- `health-cleanup.json`: `7a7bf8d384358d8942e780caf9e93861e297ac2415fe508967c358ca5018a668`
- `bound/kernel-event.jsonl`: `edc418ea5bbba50cf2273236fca1e83d33ac8fed7085b0e34557c526857adb84`
- `bound/actor-result.jsonl`: `39d613820618a44eb9cb1ca9bfbe8507b295d8acd89cc6ff9badf011becf90ff`
- `bound/scan-report.jsonl`: `b6bbf2febfd2dfa2b09dc73b8f1cdfb3d2a28aa66ef8d622d24fe69aa15a5caf`
- `clamd.conf`: `3d844404fcc5cdf46b8e2fcf831031fcf691ddcc1007b2e1ad3bcd2c6587d90a`

## Boundary

This closes only the R13 detection-deny slice using the repository test
signature database. It does not substitute for authorized production CVDs or
the required denial cases for incomplete, resource, timeout, and parser
failures. No capability was promoted and final readiness remains blocked.

State: `development-verified; fanotify-clean-and-detection-passed; denial-and-production-cvd-gates-open`
