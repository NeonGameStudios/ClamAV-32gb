# Current 32 GiB roadmap snapshot

Generated from the working-tree capability manifest and the existing release-readiness gate.
Regenerate with `python3 tools/largefile_status_snapshot.py --output 32gb-current-snapshot.md`.
Check freshness with `python3 tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md`.

**Release-readiness result: blocked.**
Counts alone do not establish release qualification. In a blocked snapshot, qualified labels
have not undergone the gate's final evidence verification. Focused tests are not full-size qualification.

| Generated measure | Value |
| --- | ---: |
| Total capability rows | 597 |
| Labeled qualified | 0 |
| Bounded | 143 |
| Pending | 440 |
| Unsupported (all kinds) | 14 |
| Unsupported required rows (still blockers) | 0 |
| Deliberate unsupported exclusions (allowlisted) | 14 |
| Release-blocking rows | 583 |
| All parser rows blocked / total | 80 / 80 |
| Enabled parser rows blocked / total | 80 / 80 |
| Unsupported required parser rows | 0 |

Enabled parser rows exclude parser rows labeled unsupported; all parser rows include them.
Required unsupported rows remain blockers. Only allowlisted `kind=unsupported` rows are exclusions.

## Roadmap reminders — maintained text, not generated findings

These reminders require human review as implementation and evidence change:

- Implementation: finish remaining modern OneNote/contiguous parser paths and independent format-8 bytecode fixtures.
- Evidence: qualify current-source Linux x86-64 Release and ASan/UBSan builds with production databases.
- Acceptance: run the oversized descriptor probe on the certified runner; complete materialized edges, ingress/on-access parity, and resource measurements.
- Release: obtain revision-bound evidence for each required capability and run the full release gate.

See [PLAN.md](PLAN.md), [audit1.md](audit1.md), and [32gb-status-summary.md](32gb-status-summary.md) for requirements and history.

## Snapshot provenance

- Capability manifest SHA-256: `08582ebcf3c8aa5e55afe48b2b8c0625973731662b12000cf0405948d54c304f`
- Readiness gate SHA-256: `d743b422d660d8ae6350e3debf7f5e997f6b6f4ecd48e5d5f7467b70e96ca95a`
- Unsupported allowlist SHA-256: `105b9437c8027ba18ab7deb78e97a883566ed112b65c61def4f3458e01d82b33`
- This tracked dashboard intentionally excludes Git HEAD; source/build identity belongs to external run provenance.
- Freshness compares this generated text and the inputs above; it does not certify the entire source tree or external evidence.
