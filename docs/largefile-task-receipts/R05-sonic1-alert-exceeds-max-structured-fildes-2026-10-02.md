# R05 Sonic1 AlertExceedsMax structured FILDESREPORT repair — 2026-10-02

Task ID / parent milestone: `R05` / `R03`, `R04`, `R10`.

Exact capability surface exercised: `clamd:FILDESREPORT`,
`feature:SERVICE_POSTRUN_EVIDENCE`. This is a sparse descriptor-size control
only; it does not qualify a materialized oversized input or any other ingress.

## Candidate and provenance

- Repository: `ClamAV-32gb`; branch: `largefile-roadmap-qualification`.
- Candidate commit: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`; working tree
  dirty state was bound in the package sidecar (157 porcelain rows; status
  SHA-256 `03e8545e233c9735733f823dcdd9eaef09bb9be76e34b52d275e9de4cc6c82e8`).
- Git-less source-content manifest SHA-256:
  `675238439dd52e021fde56508ee0aad24279b2a7f12573819a7678ff52dfc2e3`.
- Deterministic source package SHA-256:
  `d7d34bdf03a0d7bc5a93aa9807f8fc2943faf2223729cd4b50db020734f4d39f`
  (17,934,340 bytes). MCP-SSH transfer
  `transfer_abc3036bf1a64975a438a7f406cd5eed` committed atomically with the
  same final SHA-256.
- Qualification run ID:
  `R05-sonic1-alert-exceeds-max-v3-20261002-67523843`.
- Runner: Sonic1 / `sonic1-camera-key`, Linux x86-64, isolated container
  `450e8d8f297ffb0d8ace2900b2802bfb2a6f47b63ea40d1e48d0168fd7a41a6c`, image
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Release `clamd` SHA-256:
  `7b883d05389b404298d7c4c1e58627a3bc2bb5d0a6232db4f5b43d241749a449`;
  CMakeCache SHA-256
  `ffb6d807b87815dc8e02fbe3f47b60c133414a4b7191e8d0c374dd24c90426e4`.
  The unchanged Rust archive was reused at SHA-256
  `e2c62eac45cde9fd429cb561334ba6e7ebc7c291930a34a80bfeb6f281739ba2`;
  the `clamd` Release target built and linked successfully.

## Change and diagnosis

`clamd/scanner.c` now promotes a configured limit heuristic in the daemon-owned
structured report when the report itself still has a non-success
`LIMIT_INCOMPLETE` outcome. The guard requires `AlertExceedsMax`, the exact
`Heuristics.Limits.Exceeded.` alert prefix, and the incomplete report state.
It no longer gates on the scalar API return: ClamD can already return
`CL_VIRUS` for the legacy reply while the structured report retains the
underlying size-limit error. Promotion sets a successful scan status, the
potentially-unwanted verdict, and `DETECTION_TERMINATED`, while retaining the
limit reason and zero-work accounting.

## Live service results

Both daemon configurations used identical 32-GiB `MaxFileSize`, 64-GiB
`MaxScanSize`, 256-GiB matcher work, 64-GiB temporary budget, 32-GiB
contiguous/PCRE/stream limits, and the same private non-matching
`nevermatch.hdb` (SHA-256
`0375814b8af4c38fdb2b0a7eef9b288e6fb08e8f8bdfbe718a657e57088050b6`). No
production CVD was used.

The strict helper sent an exactly 34,359,738,369-byte sparse regular-file
descriptor using `FILDESREPORT` in each mode. Both calls and the combined
evidence validator exited zero. Before/after fixture metadata matched,
allocated bytes were zero, the fixture was removed, and each daemon answered
PONG before and after.

| Mode | Accepted report |
|---|---|
| `AlertExceedsMax no` | `LIMIT_INCOMPLETE`, status 24, verdict 0, no alert name; reason `Heuristics.Limits.Exceeded.MaxFileSize`. |
| `AlertExceedsMax yes` | `DETECTION_TERMINATED`, status 0, verdict 3, exact alert `Heuristics.Limits.Exceeded.MaxFileSize`. |

Accepted evidence hashes:

- Alerts-off JSON: `7a012fa94954f665b1e8b632c015f0f355f38de8a496e53a0deb8863225fb422`
- Alerts-on JSON: `e9bd65d114215c843f5a94f5df0c0b509cbd4fdfa6ce088e590118aff8a5538b`
- Combined bundle: `b6ccc0915addf082bedabf745e432eb3f10f684a1a5c557d3b0c3e5d8301c4c1`

ClamD's temporary directory used the container's disk-backed overlay path
`/tmp/r05rpt-v3-6752/tmp` because the persistent qualification LV was 279 MiB
below the admission reserve. The sparse fixture, configs, reports, and logs
were kept on the qualification LV; the report records zero temporary bytes.
Both daemons were stopped cleanly.

Artifacts are retained locally at
`/private/tmp/clamav-r05-svc-evidence-20261002/r05-service-oversize-20261002-v3/`
and on Sonic1 at
`/tmp/clamav-qualification-disk-lv-v1/r05rpt-v3-6752/`. The fresh handoff
manifest is retained locally and at
`/tmp/clamav-qualification-disk-lv-v1/qual32g-r05-alertreport-v3-67523843.handoff.json`.

## Qualification boundary

This repairs and verifies the private-database structured oversize report
pair only. It does not qualify the production-CVD canary, fully materialized
32-GiB input, independent parser corpus, sanitizer/resource matrix, other
service ingress modes, or final release readiness. No capability row was
promoted; R05 and overall release qualification remain incomplete.

State: `development-verified; sparse FILDESREPORT alert-mode pair passes; not release-qualified`.
