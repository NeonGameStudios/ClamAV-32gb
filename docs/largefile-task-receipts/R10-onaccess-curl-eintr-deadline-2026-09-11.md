# Task receipt: R10 on-access curl readiness EINTR deadline — 2026-09-11

Task ID / parent milestone: `R10` / `R00`.

Exact capability: `on-access:permission`.

Scope: preserve the configured `OnAccessCurlTimeout` when curl socket
readiness waits are interrupted by signals. This is a development-verified
transport slice; it does not claim certified service qualification.

Canonical checkout: `<repository-root>`, branch
`largefile-roadmap-qualification`. The working tree remains intentionally
dirty and existing changes were preserved. No remote execution, remote SSH,
usage reset, installation, commit, push, or GitHub workflow action was used.

Observed gap: `onas_socket_wait()` returned immediately on `EINTR`, causing
an interrupted readiness wait to become a transport failure instead of using
the configured timeout. Repeated signals also had no explicit absolute
deadline contract.

Changes:

- `onas_socket_wait()` now computes one absolute monotonic millisecond
  deadline for each readiness wait, rebuilds `fd_set` and `timeval` after
  every `EINTR`, and preserves timeout versus readiness-error
  classification.
- The clock helper follows the existing `CLOCK_MONOTONIC` project pattern,
  with a guarded POSIX fallback and no unguarded `gettimeofday()` reference
  in `_WIN32` preprocessing.
- Added a source guard requiring the deadline/retry contract to remain in the
  current on-access communication path.

Verification:

- Disposable ARM64 Docker syntax check with `-Wall -Wextra
  -Wformat-security -Werror -std=gnu90` passed for all affected C ingress
  translation units, including `clamonacc/client/communication.c`.
- `python3 -B -m unittest discover -s tools -p '*_test.py'`: 147 passed,
  2 expected skips.
- Focused clamd/report/oversize/workload checks passed: 6/6, 1/1, 22/22,
  and 28/28 with 2 expected Linux-only skips.
- `sh tools/largefile_source_guards.sh`: complete sweep passed, including 597
  capability rows and the explicit EINTR deadline guard.
- `git diff --check`: passed.
- Refreshed source-manifest identity after this slice:
  `f0f0ab9d8f92779a7602deafe87351b87524f947160cd89580277b66058f7928`.

Disposition: `development-verified`. No capability was promoted. Certified
Linux x86-64, full-size ingress/on-access evidence, sanitizer evidence, R04
authoritative records, and final release qualification remain open.
