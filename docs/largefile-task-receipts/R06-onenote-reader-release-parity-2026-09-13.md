# Task receipt: R06 OneNote reader Release parity — 2026-09-13

Task ID / parent milestone: `R06` / `R03`.

The current-source Release `check_clamav` binary was run in the existing
`clamav-current-rust-build-20260911` disposable container from
`/tmp/clamav-release-current-20260913/unit_tests` with:

```text
CK_FORK=yes CK_DEFAULT_TIMEOUT=300 CK_RUN_SUITE=cl_suite
CK_RUN_CASE=rust_onenote T=1200 ./check_clamav
```

Result:

```text
100%: Checks: 4, Failures: 0, Errors: 0
```

The four cases include initial-read and truncated-prefix fail-visible
controls, a logical input crossing the former 256-MiB whole-input cap, and a
reader-backed attachment detection above that cap. The latter verifies the
positive result comes from streamed attachment handoff and that temporary
accounting returns to zero.

Retained identities:

- source manifest SHA-256: `4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`
- Release `check_clamav` SHA-256: `395d236f58f664a2cd8bbe8718e3e1e14fc4c563d2764024ae32f75c0581f067`
- Release `CMakeCache.txt` SHA-256: `1f125879914959b31775438b6dbd865a1bf45e219c587c92ecd424df1d5b45e9`

This is ARM64 Docker development evidence and closes the local Release-side
parity gap for this focused group. It does not qualify a certified Linux
x86-64 runner, exact/materialized 32-GiB input, production CVD/service,
fanotify, resource phases, Sonic1, or final release readiness. No capability
was promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.

State: `development-verified; release-qualification-blocked`.
