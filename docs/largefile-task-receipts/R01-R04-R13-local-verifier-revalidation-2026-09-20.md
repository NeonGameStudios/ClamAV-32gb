# R01/R04/R13 local verifier revalidation — 2026-09-20

## Scope

This receipt records a fresh host-side revalidation of the current candidate's
provenance, capability-case, service, resource-phase, and fanotify evidence
verifiers after the Sonic1 materialized PCRE receipts were added. It verifies
the acceptance machinery itself; it is not certified Linux x86-64 runtime
qualification and does not promote any capability.

## Commands and results

From the clean `largefile-roadmap-qualification` worktree:

```text
sh tools/largefile_source_guards.sh
python3 -m unittest discover -s tools -p '*_test.py' -v
```

Results:

- the 604-entry capability manifest and release-readiness controls passed;
- source guards passed;
- 231 tests passed;
- 2 tests were skipped because they require Linux qualification filesystem
  controls;
- the combined unittest invocation exited 0;
- the resource-capture test retained its expected five-sample phase-watch
  control and zero exit status.

The current local commit at capture was
`bdc943ddbb65dc77d8c4aebda25de32080fa70ba`. No source or generated evidence
file was modified by the test run, and `git diff --check` remained clean.

## Boundary

This revalidation proves that the fail-closed manifest, case-binding,
provenance, resource-phase, service, and fanotify verifiers still reject weak
or contradictory evidence. It does not supply the missing current-source
Sonic1 build, certified x86-64 sanitizer parity, production-CVD canary,
materialized disk-backed matrix, full ingress matrix, or real full-size
fanotify matrix. Release readiness remains blocked and no capability was
promoted.
