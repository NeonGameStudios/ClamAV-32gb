# Task receipt: R13 on-access thread-pool lifecycle — 2026-09-12

Task ID / parent milestone: `R13` / R10.

Exact capability kind:id list: `on-access:permission` and the shared
on-access worker-queue startup/teardown contract. This receipt does not
promote any capability to release qualification.

Starting commit: `8e837b88`. The worktree already contained the roadmap
implementation and other uncommitted task files; those changes were preserved.
The post-change current source manifest contains 1,695 entries and has
SHA-256 `38e4a79612532a9360240686f59ba86c3d2ada046a82db8843bca6ec5bc57a77`.

Prerequisites verified: the existing `rust:1.97-bookworm` ARM64 development
container was reused with the current checkout mounted at `/src`. The existing
out-of-tree Release build at `/tmp/clamav-release-current-20260912` was
reconfigured from the current source and has clamonacc, milter, UnRAR, and
pthreads enabled. No software was installed.

Observed lifecycle defect: `thread_init()` ignored `pthread_create()` failure,
and `thpool_init()` then waited forever for a worker that could never become
alive. Detached workers also made cleanup of a partially initialized pool
unsafe. This is fail-open for on-access permission events because startup can
stall while ownership and response cleanup remain unresolved.

Changes made:

- Check `pthread_create()` and release the worker allocation on failure.
- Keep successfully created workers joinable and join them during both partial
  initialization failure and normal pool teardown.
- Replace the initialization spin with a condition-variable wait for all
  workers to publish readiness.
- Make the shutdown path wake the binary-semaphore waiters until every worker
  has exited before queue or pool memory is released.
- Add a Linux linker-wrapped `EAGAIN` regression proving failed worker
  creation returns `NULL` promptly, while retaining the zero/negative-size and
  normal one-worker execution checks.
- Extend source guards and refresh `docs/largefile-inventory.tsv`.

Commands and observed results:

- Reconfigure and build `check_onas_threadpool` plus `clamonacc` — exit 0.
- Direct injected-failure/normal-execution test under a 15-second timeout —
  exit 0; the expected `pthread_create` failure was reported.
- Focused CTest (`largefile_onaccess_threadpool`,
  `largefile_onaccess_config_admission`) — `2/2` passed.
- Full configured CTest — `26/26` passed in `168.09` seconds.
- `sh tools/largefile_source_guards.sh` — exit 0.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md` — exit 0.
- `git diff --check` — exit 0.

Rebuilt artifact hashes:

- `clamonacc`: `fc3e3b1cea10ef9b5e785838a36db2dc61bd2e33c9cb559056b49e1baca4af71`
- `check_onas_threadpool`:
  `9b2aee3886ece03d0822895baaa8b7bbafd4cc79b5324f8f08a0ecb897e5b841`

Full-size/certified evidence produced, or explicitly not run: no release
qualification evidence was produced. The available runner is Linux ARM64 and
cannot satisfy the roadmap's certified Linux x86-64, exact 32-GiB, sanitizer,
production-CVD, Sonic1, resource-sidecar, or privileged fanotify permission
requirements. The independent R07 format-8 compiler/artifact prerequisite is
also still open.

State: `development-verified; qualification-blocked-by-runner-and-fixtures`
