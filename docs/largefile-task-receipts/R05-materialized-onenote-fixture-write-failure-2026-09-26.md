# R05 materialized OneNote fixture write-failure handling — 2026-09-26

Task ID / parent milestone: `R05` / `R00`, fixture-generation support for the
pending `feature:onenote-modern-over-256m` capability.

Exact capability kind:id list: `feature:onenote-modern-over-256m`. This task
hardens fixture generation only; it does not qualify the capability or prove a
32-GiB scan.

Starting commit and working-tree/source identity: branch
`largefile-roadmap-qualification`, commit
`5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`; pre-existing dirty changes were
preserved. Post-change source-content manifest SHA-256 is
`ee971b35d6704fb26144115e0ec1a68381dd0fc43909d5eb43230c6e6e80c5b8` (1,711
entries). This identifies the dirty tree's content but is not a clean commit or
qualification candidate.

Prerequisites verified: the deterministic OneNote late-child generator writes
materialized payloads and is used for inputs larger than its historical
256-MiB reader boundary. A short write or storage error previously could leave
the destination pathname occupied by a partial fixture, obscuring the failure
and blocking a clean retry.

Owned files and excluded shared files: `tools/largefile_onenote_late_fixture.py`
and `tools/largefile_onenote_late_fixture_test.py`. No scanner implementation,
capability manifest, roadmap contract, or release evidence was changed.

Observed failure and expected behavior: simulated failure after the fixture
output was created. The generator must retry short writes, remove its own
partial output, preserve any unrelated inode substituted at the destination,
and report when cleanup itself fails so a possible leftover cannot be mistaken
for a completed fixture.

Changes made: added a complete-write helper; retained the created file's inode
identity; checked the final path type, identity, and byte count; and added
best-effort failure cleanup that only unlinks the original output inode. A
cleanup failure now reports that the partial path may remain. Added mutually
exclusive `--payload-bytes` and `--target-bytes` options, so a caller can request
an exact 32-GiB final file without external size arithmetic. Regression tests
cover exact-size arithmetic, rejection below the large-fixture floor, short
writes, no-progress writers, write-failure cleanup, replacement preservation,
and cleanup-failure reporting.

Commands and exits:

- `PYTHONPATH=tools python3 -B -m unittest largefile_onenote_late_fixture_test`
  — exit 0, 10 tests passed. The exact 32-GiB target calculation test creates
  no large file; the 256-MiB materialized fixture regression now exercises
  the public CLI using `--target-bytes` and independently checks output size,
  marker placement, and allocated bytes.
- `RUSTUP_TOOLCHAIN=stable CARGO_NET_OFFLINE=true CARGO_TARGET_DIR=/private/tmp/clamav-onenote-target-20260926 cargo test --manifest-path libclamav_rust/onenote_parser/Cargo.toml --offline`
  — exit 0, 85 parser unit tests and 6 integration tests passed; 1 doctest was
  ignored. The integration suite includes logical input above the former
  256-MiB whole-input cap and short-read parity. This is local development
  evidence, not certified x86-64 or 32-GiB evidence.
- `git diff --check` — exit 0.
- `sh tools/largefile_source_manifest.sh "$PWD" <temporary-output>` — exit 0;
  recomputed post-change content manifest hash matches the identity above.
- Deterministic source candidate archive: 18,370,536 bytes, SHA-256
  `312d2d0dea648ec8d7d3cc0868bf04b4fcfe0b2a4da788f71c2ad56f289aed7c`;
  a separately generated repeat was byte-identical. Extracting the archive and
  regenerating its 1,711-entry source manifest produced byte-identical output
  with SHA-256 `ee971b35d6704fb26144115e0ec1a68381dd0fc43909d5eb43230c6e6e80c5b8`.
- `sh tools/largefile_source_guards.sh` on the extracted package — exit 0;
  the generated dashboard was recreated in the extracted tree before running
  the full source guards and their embedded test suites.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md`
  — exit 0 in the working tree.

Full-size/certified evidence produced, or explicitly not run: no 32-GiB fixture
was generated in this slice. Sonic1's separately tracked RAM-fixture write is
  still marked running by the MCP-SSH job ledger, with remote execution
  unconfirmed due SSH/SFTP timeouts. The latest job-status request timed out
  after 30 seconds during SSH Connect; the cancel result remains unconfirmed.
  No new remote job or transfer was started and no software was installed.

Remaining failures / next slice: generate and independently validate the exact
fully materialized OneNote edge fixture on the authorized Linux x86-64 runner;
run it against the current immutable Release and sanitizer candidate; retain
the expected late-child signature/offset and resource, cleanup, and provenance
evidence. The authoritative release-readiness matrix remains blocked.

State: `development-verified; not release-qualified`

## Sonic1 handoff recheck — 2026-09-26 13:19 UTC

- MCP-SSH's control plane is responsive. A fresh job-ledger query still reports
  the same tracked `dd` job as `running`, `remote_may_still_be_running=true`,
  PID `16038`; no replacement or cancellation was inferred.
- The configured host/profile resolves to `192.168.1.216:4456` with the
  administrator-provided `sonic1-camera-key` profile. The SSH status request
  timed out after 30 seconds during `Connect` (`req_b414791cb1da45ef8e208e3deb127635`);
  a bounded stdout retrieval separately timed out during `Sftp`
  (`req_8929e47bc5e6404d909ef7e4afc69144`).
- Host metadata reports SSH host-key verification disabled and SFTP as root
  via sudo; this is recorded as configured risk, not treated as evidence of a
  successful connection. No upload, new command, fixture, scan, restart, or
  cleanup was started. Reconcile this exact job/container before any new
  remote mutation when SSH access returns.
