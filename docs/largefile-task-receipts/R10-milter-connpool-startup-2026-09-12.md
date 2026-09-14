# Task receipt: R10 milter connection-pool startup — 2026-09-12

Task ID / parent milestone: `R10` / milter ingress and service parity.

Exact capability kind:id list: `milter:message` and the milter startup
connection-pool contract. This receipt does not promote any capability to
release qualification.

Starting commit and working-tree/source manifest identity: starting commit
`8e837b88`; the worktree already contained the roadmap implementation and
uncommitted task files. The post-change source manifest SHA-256 is
`38c4763f8df4a5ba68f9523cfa5ddd72cf3933c42dc6ac47da61a0be7654765c`.

Prerequisites verified: the existing `rust:1.97-bookworm` ARM64 development
container was reused with the current checkout mounted at `/src`. The existing
Release build at `/tmp/clamav-release-current-20260912` was regenerated and
reused. No software was installed.

Observed failing case and expected behavior: `cpool_init()` previously ignored
failure from its monitor-thread `pthread_create()` call. That left `cp` non-null
with no monitor and allowed milter startup to continue with an unusable
connection pool. A configured milter must fail initialization and clean up if
the monitor cannot start.

Changes made:

- Make `cpool_init()` return an explicit status and check all initialization
  failure paths.
- Reject monitor-thread creation failure, free the partially initialized pool,
  and make `clamav-milter` abort startup.
- Add a Linux linker-wrapped `EAGAIN` regression covering failed startup,
  successful startup, and monitor cleanup.
- Register the regression in CTest, add source guards, and refresh the tracked
  inventory.

Commands, exits, and hashes:

- Regenerate CMake and build `check_milter_connpool` and `clamav-milter` — exit
  0.
- Direct injected monitor-thread failure regression — exit 0.
- Focused milter CTest (`largefile_milter_connpool`, quota, protocol) — `3/3`
  passed.
- Complete configured current-source ARM64 Release CTest matrix — `28/28`
  passed in `272.76` seconds.
- Final `sh tools/largefile_source_guards.sh` — exit 0.
- Final snapshot freshness check and `git diff --check` — exit 0.
- Rebuilt `clamav-milter` SHA-256:
  `1febe7d2239deecf266005fa96dfd52fbc4c2623ded08f028910533923e8e525`.
- Rebuilt milter regression SHA-256:
  `9dac3885b9ec66aa95c7d13b3da9623d2c5aff3b2e8634fee1de2fbcd72b863c`.

Full-size/certified evidence produced, or explicitly not run: not produced;
the available container is Linux ARM64 and cannot satisfy the roadmap’s
certified Linux x86-64, exact 32-GiB, sanitizer, production-CVD, Sonic1,
resource-sidecar, or privileged fanotify permission requirements.

State: `development-verified; qualification-blocked-by-runner-and-fixtures`.
