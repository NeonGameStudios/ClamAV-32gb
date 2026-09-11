# Task receipt: R10 quarantine destination-path size hardening

Task ID / parent milestone: `R10` / `R00`

Exact capability kind:id list: ingress:`clamscan`, ingress:`clamdscan`,
ingress:`milter`, ingress:`on-access`

Starting commit and working-tree/source manifest identity: branch
`largefile-roadmap-qualification`; existing dirty working tree preserved; the
generated inventory and snapshot were refreshed after this slice.

Prerequisites verified: the common quarantine copy/move paths were inspected;
both collision-suffix loops used unchecked allocation arithmetic and
`sprintf()`. No dependency installation, remote runner, Docker execution,
usage reset, commit, push, or GitHub workflow action was used.

Owned files and excluded shared files: owned `common/actions.c`, its source
guards, and roadmap receipt metadata. Shared release labels and qualification
records were not promoted.

Observed failing case and expected behavior: a quarantine filename and
directory are combined into a returned destination path before the action
opens or links the file. Length overflow or formatting truncation must fail
closed before the destination path is used, including collision suffixes
`.001` through `.999`.

Changes made:

- Added one checked destination-path builder for move/copy and hard-link
  quarantine flows.
- Checked `size_t` arithmetic, the suffix range, `snprintf()` result, and the
  `INT_MAX` representability boundary before replacing the prior allocation.
- Removed all `sprintf()` calls from `common/actions.c` and added source guards
  for the shared builder and fail-closed checks.

Commands, exits, logs and fixture/database hashes:

- `git diff --check` — run before the source gate.
- Inventory, snapshot freshness, the 145-test tools suite, and the complete
  source/evidence guard sweep passed after this source change.
- A linked current-source C build was not available on this host because the
  development environment lacks required OpenSSL headers; no software was
  installed.

Development tests passed: source/evidence controls passed; no linked action
consumer binary was available for runtime execution.

Full-size/certified evidence produced, or explicitly not run: not run. No
current-source CMake build, Linux x86-64 Release/sanitizer build, production
database, materialized large-file edge, or R04 qualification record exists for
this slice.

Remaining failures / next slice: certified ingress execution, full-size
materialized service cases, and release qualification remain open.

State: development-verified
