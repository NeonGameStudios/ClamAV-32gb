# R04/R11 current-source Release acceptance refresh — 2026-09-13

Task IDs / parent milestones: `R04`, `R11` / `R03`, `R10`.

Purpose: refresh the direct CLI and daemon/client development acceptance
bundles after the source-manifest generator correction. Both captures used
the same current-source ARM64 Release build.

Source identity: branch `largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. The current-source manifest contains 1,697 entries
and has SHA-256
`1664c22ff783fd269c2c0e12e21ba81e05ce6c603fff66fe8a0530d68b87093d`.

Environment:

- Existing Docker container `clamav-current-rust-build-20260911` was reused;
  no software was installed.
- Release build: `/tmp/clamav-release-current-20260913`.
- CMake cache SHA-256:
  `02247cc5b5e03df77fa916eb316eb6fc2933b12dc5ec208c764be5bb26ebd973`.
- Service bundle: `/tmp/clamav-r04-service-release-current-20260913b/`.
- Direct CLI bundle: `/tmp/clamav-r04-clamscan-release-current-20260913b/`.

Verification:

- The service capture exited 0 and wrote 36 R04 records across six structured
  report commands and six `clamdscan` modes: 12 `COMPLETE`, 12
  `DETECTION_TERMINATED`, and 12 `LIMIT_INCOMPLETE`.
- Independent validation exited 0: `large-file acceptance record schema
  passed (36 records)`.
- The direct `clamscan` capture exited 0 and wrote six records: two each of
  `COMPLETE`, `DETECTION_TERMINATED`, and `LIMIT_INCOMPLETE`.
- Independent validation exited 0: `large-file acceptance record schema
  passed (6 records)`.
- Service artifacts retain health/cleanup lifecycle evidence for all three
  outcome groups. Acceptance record hashes are `9d3d860056f36aabe2d956e4f4a0817bb0da106a2f1031f65eb82893597e69be`
  (service) and `ef2ad62b2e2093491c9639c8d42c071184ccb6787e66e5cbd2fa992f4a013f4d`
  (direct CLI).

Qualification boundary: these are current-source ARM64 Docker development
records using small private fixtures. They do not prove exact 32-GiB or
materialized service behavior, certified Linux x86-64 resource limits,
production CVD, privileged fanotify, Sonic1, or final release qualification.
No capability was promoted.

No usage reset, commit, push, or GitHub workflow action was used.

State: `development-verified; qualification-blocked-by-runner-and-fixtures`.
