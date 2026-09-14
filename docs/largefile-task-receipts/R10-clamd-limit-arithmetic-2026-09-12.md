# Task receipt: R10 clamd numeric limits and queue arithmetic — 2026-09-12

Task ID / parent milestone: `R10` / daemon ingress and scheduling.

Exact capability kind:id list: `service:clamd` and the clamd numeric-option and
queue-limit admission contract. This receipt does not promote any capability
to release qualification.

Starting commit and working-tree/source manifest identity: starting commit
`8e837b88`; the worktree already contained the roadmap implementation and
uncommitted task files. The post-change current-source manifest contains 1,696
entries and is SHA-256
`4a5c5e7544f752830511a833b4467106708e2b7c848b4862c4c18e6695107546`.

Prerequisites verified: the existing `rust:1.97-bookworm` ARM64 development
container was reused with the current checkout mounted at `/src`. The existing
Release build at `/tmp/clamav-release-current-20260912` was reconfigured and
rebuilt. No software was installed.

Observed risk and expected behavior: daemon numeric options were parsed with
`atoi()`, allowing values to narrow or overflow before validation. Queue-limit
derivation also multiplied recursion and thread settings and subtracted the
result from the file-descriptor limit without checked arithmetic. Invalid or
overflowing input must be rejected, and a valid queue ceiling must be computed
without wraparound or unsigned underflow.

Changes made:

- Parse generic numeric options with checked `strtoll()` conversion in both
  configuration parser paths, rejecting range errors and trailing characters.
- Add a checked clamd queue-limit calculator that validates representable
  thread and queue counts, detects multiplication and descriptor-budget
  overflow, avoids underflow when the descriptor limit is too small, and caps
  the effective queue at `INT_MAX`.
- Validate raw `MaxThreads` and `MaxQueue` values before narrowing them to the
  daemon thread-pool types and use the checked calculator for the descriptor
  budget.
- Add unit coverage for parser overflow and queue arithmetic edge cases,
  including `UINT64_MAX`, low descriptor limits, and multiplication overflow.
- Add source guards and refresh the tracked large-file inventory.

Commands, exits, and hashes:

- Reconfigure and build `check_clamd`, `clamd`, and `clamscan` — exit 0.
- Complete configured current-source ARM64 Release CTest matrix — `28/28`
  passed in `215.36` seconds, including library, Rust, CLI, daemon,
  freshclam, sigtool, milter, acceptance/evidence, procfs, OOM, and service
  evidence suites.
- Source guards as CTest test `#7` — exit 0. The redundant host-side guard
  rerun was stopped after exceeding its normal runtime without failure output;
  the post-receipt snapshot freshness check — exit 0.
- `git diff --check` — exit 0.
- Rebuilt `clamd` SHA-256:
  `4987317230e2f455e4de8b46782864fe3054b8e74666f029445e433420041370`.
- Rebuilt `check_clamd` SHA-256:
  `7f4267b0aceb56946fd55e171acec034627df726921d4c15551fe8ccddabe27c`.

Full-size/certified evidence produced, or explicitly not run: not produced;
the available container is Linux ARM64 and cannot satisfy the roadmap’s
certified Linux x86-64, exact 32-GiB, sanitizer, production-CVD, Sonic1,
resource-sidecar, or privileged fanotify permission requirements.

Readiness after this slice: `capability_total=601`,
`capability_qualified=0`, `capability_bounded=147`, `capability_pending=440`,
`capability_unsupported=14`, `capability_blocked=587`,
`parser_blocked=80`, `release_readiness=blocked`.

State: `development-verified; qualification-blocked-by-runner-and-fixtures`.
