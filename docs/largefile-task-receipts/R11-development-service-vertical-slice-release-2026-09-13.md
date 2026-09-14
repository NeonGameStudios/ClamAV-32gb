# R11 current-source Release service vertical slice — 2026-09-13

Task ID / parent milestones: `R11` / `R04`, `R10`.

Scope: current-source Release `clamd` and `clamdscan` service behavior over
clean, exact-detection, and configured-limit fixtures. The direct protocol
set covered `SCANREPORT`, `CONTSCANREPORT`, `MULTISCANREPORT`,
`ALLMATCHSCANREPORT`, `FILDESREPORT`, and `INSTREAMREPORT`. The client set
covered default, fdpass, stream, multiscan, stream-multiscan, and
fdpass-multiscan modes.

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
- Service evidence output (outside the source tree):
  `/tmp/clamav-r04-service-release-current-20260913/`.
- Build CMakeCache SHA-256:
  `896566415d30f389249b746b177d369132e48f12fdd2b201114cbfdbef69b175`.
- Build identity SHA-256:
  `f3dd82fe6b0a6bb9d0fb01be094b53b61fa3cda51b3aab18a944fa9bf3f1f3ad`.
- Source-manifest artifact SHA-256:
  `c75877cc35ffc2d86a4a7c086cc2a51a80e026ec96a5e047ec223e98942246d9`.
- Acceptance-record TSV SHA-256:
  `409365761774f67330eafe0472ad12b9e65824a97d5e9506fe0b6cf6e1b1766f`.
- Service-input identity SHA-256:
  `7236443c0b8ca24c0d1c9c7c381d5dedca1a0a1b3fa3d37c3ecc3a80228b174b`.

Verification:

- The live capture exited 0 and wrote 36 R04 records: 12 `COMPLETE`, 12
  `DETECTION_TERMINATED`, and 12 `LIMIT_INCOMPLETE`.
- Independent record validation against the current manifest and case map
  exited 0: `large-file acceptance record schema passed (36 records)`.
- All three outcome groups retained daemon lifecycle artifacts proving health
  before and after the run, normal exit, and socket/PID cleanup.

Qualification boundary: this is current-source ARM64 Docker development
evidence using small private fixtures. It does not prove exact 32-GiB or
materialized service behavior, certified Linux x86-64 resource limits,
production CVD coverage, milter, privileged fanotify, Sonic1, or final
release qualification. No capability was promoted.

State: `development-service-verified; qualification-blocked-by-runner-and-fixtures`.
