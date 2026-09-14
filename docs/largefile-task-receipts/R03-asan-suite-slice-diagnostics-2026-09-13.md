# Task receipt: R03 ASan/UBSan suite-slice diagnostics

Task ID / parent milestone: `R03`

The existing ARM64 ASan/UBSan build remained bound to the current 1,697-entry
source manifest, SHA-256
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f`.

To narrow the known aggregate `libclamav` sanitizer timeout without changing
its timeout contract, current-source Check TCase slices were run with
`CK_RUN_SUITE=cl_suite` and `T=60`:

- `egg_map`: 16/16 checks passed.
- `7z`: 28/28 checks passed.
- `rust_onenote`: 4/4 checks passed.
- `zip`: 19/19 checks passed.
- `pdf`: 24/24 checks passed.

No slice reported a failed or errored check. The full aggregate
`libclamav` sanitizer target remains unverified within its 1,200-second
aggregate budget; the prior diagnostic log reached the `egg_map` boundary
without an assertion or sanitizer diagnostic. These slices therefore narrow
the issue to aggregate runtime/profile or the remaining unrun groups, but do
not turn a partial decomposition into a full-suite pass.

The Docker container used for these diagnostics had exited cleanly with exit
0 and `oom=false`; it was restarted only to continue the bounded tests. No
source or build configuration was changed by that restart.

This is ARM64 development evidence only. Certified Linux x86-64, exact
32-GiB/materialized resources, production-CVD/service, privileged fanotify,
Sonic1, independent format-8 execution, and final release readiness remain
open. No capability was promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
