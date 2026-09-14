# Task receipt: R11 development service vertical slice — 2026-09-12

Task ID / parent milestone: `R11` / `R04`, `R10`.

Exact capability kind:id list: development ingress slice for `clamd` report
commands (`SCANREPORT`, `CONTSCANREPORT`, `MULTISCANREPORT`,
`ALLMATCHSCANREPORT`, `FILDESREPORT`, `INSTREAMREPORT`) and `clamdscan`
(`default`, `fdpass`, `stream`, `multiscan`, `stream-multiscan`,
`fdpass-multiscan`). This receipt does not promote any capability to release
qualification.

Starting commit and working-tree/source manifest identity: starting commit
`8e837b88`; the worktree was already dirty with the roadmap implementation and
uncommitted task files. The current-source manifest generated in the same
container is SHA-256
`db0436a0075277db4b1b5d8a803cda39a964a715c8e9ca2d1b7307224fd51b86`.

Prerequisites verified: current source was mounted at `/src`; the existing
`rust:1.97-bookworm` build container held a coherent Release build at
`/tmp/clamav-release-current-20260912`; `clamd`, `clamdscan`, and the test CA
were present. The container platform was `Linux-aarch64`, so certified x86-64
and exact 32-GiB evidence were not claimed.

Owned files and excluded shared files: no application source files were
changed. The existing `tools/largefile_development_service_capture.py` was run
unchanged; evidence was retained outside the repository at
`/private/tmp/clamav-r04-service-current-20260912/`.

Observed case and expected behavior: for deterministic clean, detection, and
small configured-limit fixtures, each direct report command and each client
mode must return the matching structured completion (`COMPLETE`,
`DETECTION_TERMINATED`, or `LIMIT_INCOMPLETE`), exact alert/offset where
applicable, and a healthy daemon lifecycle. A limit result must not be
reported as clean.

Changes made: none to production code. The live capture produced 36 bound R04
records (12 per completion class), including daemon PING-before/after and
cleanup evidence for each outcome group. The record file was independently
revalidated against the current capability case map.

Commands, exits, logs and fixture/database hashes:

- `docker start clamav-current-rust-build-20260911` — exit 0.
- Current-source service capture with all six report commands and six
  `clamdscan` modes — exit 0; `development service capture wrote 36 R04
  records`.
- `python3 -B` acceptance-map/record validation against the copied bundle —
  exit 0; `acceptance_records_validated=36`.
- Retained build identity SHA-256:
  `29f2cd22d7622402c42c6a92559533ae53923c6834913ec592b350e11759e44d`.
- Retained acceptance-record TSV SHA-256:
  `94781dddd276126c4f0abbb53d3e61d7658285b5dbf643b602c6d209ae0a5de7`.
- All three lifecycle TSVs prove PING-before/after, daemon exit, socket
  removal, and PID-file removal.

Development tests passed: 36 live current-source service records validated;
the complete configured CTest matrix had already passed 24/24 after the same
source rebuild.

Full-size/certified evidence produced, or explicitly not run: not produced;
the ARM64 development container cannot satisfy the roadmap's certified
Linux-x86-64 and exact-edge admission requirements.

Remaining failures / next slice: bind resource sidecars after a certified
runner is available, then execute the materialized 32-GiB matrix and
production-CVD/Sonic1 canary. R07's independent format-8 artifact and R13's
privileged fanotify permission-event evidence remain external prerequisites.

State: `development-verified; qualification-blocked-by-runner-and-fixtures`
