# Task receipt: R09 required-parser policy Release parity — 2026-09-13

Task ID / parent milestones: `R09` / `R03`, `R08`.

The complete current-source Release `required_unsupported` Check group was
run in the existing `clamav-current-rust-build-20260911` disposable ARM64
container from `/tmp/clamav-release-current-20260913/unit_tests`:

```text
CK_FORK=yes CK_DEFAULT_TIMEOUT=300 CK_RUN_SUITE=cl_suite
CK_RUN_CASE=required_unsupported T=1200 ./check_clamav
```

Result:

```text
100%: Checks: 57, Failures: 0, Errors: 0
```

The group covers the seven R09 rows that remain in scope: RAR/RAR-SFX
backend/unavailable behavior, `CL_TYPE_IGNORED`, compiled Python, AI-model
structural parsing, and fuzzy-image admission/matching controls. It includes
raw-matching precedence and fail-visible malformed/unsupported behavior.

Retained identities:

- source manifest SHA-256: `4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`
- Release `check_clamav` SHA-256: `395d236f58f664a2cd8bbe8718e3e1e14fc4c563d2764024ae32f75c0581f067`
- Release `CMakeCache.txt` SHA-256: `1f125879914959b31775438b6dbd865a1bf45e219c587c92ecd424df1d5b45e9`

This closes the local Release-side parity gap for the R09 development suite.
It is not capability-specific release qualification: certified Linux x86-64,
full-size/materialized inputs, production CVD/service, resource phases,
Sonic1, and final R04 evidence remain open. No capability was promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.

State: `development-verified; release-qualification-blocked`.
