# R03 — Source-guard portability

Date: 2026-09-19
Task ID / parent milestone: `R03` / registered regression environment

## Change

`tools/largefile_source_guards.sh` now selects `rg` when available and falls
back to POSIX `grep` for fixed-string, count, line-order, and workflow-regex
checks. The guard remains dependency-free and does not install a search tool.

## Verification

The complete source-guard wrapper passed with the normal local `rg` path:

```text
large-file capability manifest passed (604 entries)
large-file release readiness tests passed
large-file acceptance case map passed (604 capabilities)
large-file acceptance record schema passed (0 records)
large-file source guards passed
exit=0
```

The same wrapper passed with `PATH=/usr/bin:/bin`, which removes the local
`rg` installation and exercises the `grep` fallback:

```text
large-file source guards passed
exit=0
```

`sh -n tools/largefile_source_guards.sh`, `git diff --check`, and the local
working-tree checks also passed.

## Sonic1 boundary

The tested script was staged to `/tmp` on Sonic1 and copied into the
disposable bind-mounted source tree with the supplied sudo-enabled profile.
The copy completed successfully. A subsequent attempt to run the remote
wrapper failed before execution because MCP-SSH timed out during SSH connect;
no remote test result is claimed and no software was installed.

This corrects the false negative observed in the prior registered CTest run,
but does not change the R03 boundary: the remote CTest result still needs a
fresh run against an identity-matched source tree before it can support any
qualification claim.

State: `development-verified`; qualification pending.
