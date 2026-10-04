# R13 Sonic1 current-candidate fanotify detection denial — 2026-09-21

## Scope and provenance

This receipt records a fresh real Linux fanotify detection-denial run against
the current packaged worktree. It uses the repository test-signature database
and is not production-CVD evidence.

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
- Fixture: `CLAMAV-TEST-STRING-NOT-EICAR`.
- Fixture SHA-256: `e529e808342de154e3788b12554b23b6bfa1ca0af604e35b00ab51d0dc126f04`.
- Runner output: `/build/fanotify-detection-current-20260921`.

## Result

MCP-SSH job `job_42a14cdf676a4d0e9043409909ade48f` exited 0. The result was:

```json
{"case_name":"detection","completion":"DETECTION_TERMINATED","permission_response":"FAN_DENY","scan_exit_code":1}
```

The non-root actor was denied. The scan report recorded `Virus(es) detected`
and `NDB.Clamav-Unit-Test-Signature.UNOFFICIAL` at offset 0, with status 1,
zero skipped operations, and `DETECTION_TERMINATED`. Startup and cleanup
health passed; clamd and clamonacc exited cleanly and PID/socket artifacts were
absent.

Retained artifact hashes:

- `result.json`: `432d5726cc8007036c582cb43f070efecc759083e47a3250fde0a884cddfb06e`
- `provenance.json`: `505040b357d2da8cf0b1f08728ab393ee6f3c1c9d68c8e177baa980f96266d25`
- `health-cleanup.json`: `7a7bf8d384358d8942e780caf9e93861e297ac2415fe508967c358ca5018a668`
- `raw/clamonacc-permission.jsonl`: `cdec2f597fd4c12bac09ccfb1444d05838f19fbcaa32312f84913ad80a184a01`
- `raw/clamonacc-report.jsonl`: `f22479e926a8538533170b12824664a07babc2ab82263098883413439bec5b92`
- `clamd.conf`: `9f66e8b5130dcf92bc2870290253fdd2e4e7fe0f196360d4c2cf8545f4723b26`

## Boundary

This is development verification only and does not substitute for authorized
production CVDs. No capability was promoted; incomplete/resource/timeout/
parser, service, materialized 32-GiB, sanitizer, and final readiness gates
remain open.

State: `development-verified; current-fanotify-detection-deny-passed; release-gates-open`
