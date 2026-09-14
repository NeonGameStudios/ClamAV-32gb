# Task receipt: R03 current-source Release CTest after provenance rebind

Task ID / parent milestone: `R03`

The existing ARM64 Release tree at `/tmp/clamav-release-current-20260913`
was reconfigured and rebuilt after its `source-manifest.txt` was found to be
stale. It now matches the current source manifest SHA-256
`4b6322c8c14e0f9175eae930cb7e5bd03e220d59977306696792ee3ff275f02f` in both
the build artifact and `CLAMAV_SOURCE_MANIFEST_SHA256` CMake cache entry.

Verification was completed in two controlled CTest invocations because the
disposable container's configured `sleep 3600` lifetime expired during the
first invocation. The first invocation passed targets 1 through 25,
including `libclamav`, all large-file controls, the ZIP late-member test,
Rust, milter, and `clamscan`. Docker reported `oom=false`; the process ended
with exit 137 only when the container lifetime elapsed while starting target
26 (`clamd`). After restarting the same container, the targeted remaining
invocation passed `clamd`, `freshclam`, and `sigtool` 3/3.

The resulting target coverage is 28/28 passed across the two invocations. No
source or build options were changed during the rebind, and no sanitizer
diagnostics were involved in this Release verification.

This is ARM64 development evidence only. Certified Linux x86-64, exact
32-GiB/materialized edges, production CVD/service, privileged fanotify,
independent format-8, Sonic1, resource sidecars, and final release evidence
remain open. No capability was promoted.

No software was installed, no usage reset was used, and no commit, push, or
GitHub workflow action was performed.
