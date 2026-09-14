# R04 current-source Release clamscan vertical slice — 2026-09-13

Task ID / parent milestones: `R04` / `R03`, `R10`, `R11`.

Scope: direct `clamscan` file and stdin ingress using clean, exact-detection,
and configured-limit fixtures. The six resulting records exercise the R04
completion contract without conflating a limit result with a clean prefix.

Source identity: branch `largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. The current-source manifest contains 1,697 entries
and has SHA-256
`c75877cc35ffc2d86a4a7c086cc2a51a80e026ec96a5e047ec223e98942246d9`.

Environment and retained evidence:

- Existing Docker container `clamav-current-rust-build-20260911` was reused;
  no software was installed.
- Current-source ARM64 Release tree:
  `/tmp/clamav-release-current-20260913`.
- Evidence output (outside the source tree):
  `/tmp/clamav-r04-clamscan-release-current-20260913/`.
- Build CMakeCache SHA-256:
  `896566415d30f389249b746b177d369132e48f12fdd2b201114cbfdbef69b175`.
- Build identity SHA-256:
  `ac2de0e647908f4069f621938f73cd018cba569cd6868f2992dc7081bd00b397`.
- Acceptance-record TSV SHA-256:
  `320644fb5088d25d0eabee44baed3011fba8d7d97a65a82b96931670cebf4fd7`.

Verification:

- The live capture exited 0 and wrote six R04 records: two `COMPLETE`, two
  `DETECTION_TERMINATED`, and two `LIMIT_INCOMPLETE`.
- Independent validation against the current manifest, case map, and retained
  artifacts exited 0: `large-file acceptance record schema passed (6 records)`.

Qualification boundary: this is current-source ARM64 Docker development
evidence using small private fixtures. It does not prove exact 32-GiB or
materialized ingress, certified Linux x86-64 resource limits, production CVD,
privileged fanotify, Sonic1, or final release qualification. No capability was
promoted.

State: `development-verified`.
