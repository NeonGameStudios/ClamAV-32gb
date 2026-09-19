# R03 — Inventory fallback portability

Date: 2026-09-19
Task ID / parent milestone: `R03` / registered regression environment

## Change

The Python fallback in `tools/largefile_inventory.sh` now mirrors the
repository's ignored generated roots: VCS metadata, `target`,
`largefile-evidence`, `largefile-corpus`, and root-level `build*` directories
are excluded before scanning. This keeps fallback inventory generation aligned
with the normal `rg` path when a build directory is present in the source
root.

## Local verification

With `rg` removed from `PATH`, the fallback inventory matched the committed
inventory exactly, and the complete source-guard wrapper passed:

```text
inventory_grep_fallback=pass
large-file acceptance case map passed (604 capabilities)
large-file acceptance record schema passed (0 records)
large-file source guards passed
source_guard_grep_fallback_exit=0
```

Shell syntax and `git diff --check` also passed.

## Sonic1 diagnosis

The prior remote guard failure was traced with a temporary wrapper. The
fallback itself passed its fixed-string checks and then rejected the remote
committed inventory as stale. Before alignment, the remote regenerated
inventory was 103,329 lines versus the committed 45,571-line file, because the
remote source root contained ignored build material.

After the fallback update, the remote regenerated inventory reduced to 45,575
lines. The current local inventory was copied into the disposable bind mount
with verified 64-KiB byte/SHA-256 chunks; the remote regenerated file still had
a different SHA-256 despite the matching line count. This proves the remote
source tree is not identity-matched to the local candidate. No remote
qualification claim is made, and no software was installed.

State: `development-verified`; qualification pending.
