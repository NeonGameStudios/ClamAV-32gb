# Task receipt: R10 on-access FD-pass timeout parity — 2026-09-11

Task ID / parent milestone: `R10` / `R00`.

Scope: close the on-access local-socket FD-passing timeout gap without claiming
certified service qualification.

Canonical checkout: `<repository-root>`, branch
`largefile-roadmap-qualification`. The working tree was intentionally dirty
and existing changes were preserved. No remote execution, remote SSH, usage
reset, commit, push, or GitHub workflow action was used.

Changes:

- `onas_get_sockd()` now creates a nonblocking Unix socket and bounds an
  in-progress connect with `OnAccessCurlTimeout`, preserving `CL_ETIMEOUT`
  versus `CL_ECREAT` in the caller.
- The on-access FILDES command and SCM_RIGHTS descriptor send now use
  nonblocking writes, writable readiness, a single deadline per operation, and
  explicit timeout/write failure classification. Short descriptor sends remain
  failures.
- The descriptor path passes the configured timeout through the complete
  connect/send sequence and retains existing close-on-all-exits cleanup.
- `tools/largefile_source_guards.sh` now proves the socket becomes nonblocking
  before connect and that deadline checks precede the actual `send()` and
  `sendmsg()` calls.
- The capability rows for on-access, milter, clamdscan stdin, OneNote, the
  bounded model parsers, and Python marshal status now reflect the current
  implementation while remaining `pending` for release qualification.

Verification:

- Disposable Docker `rust:1.97-bookworm` syntax checks passed with
  `-Wall -Wextra -Wformat-security -Werror -std=gnu90` for
  `clamonacc/client/socket.c` and `clamonacc/client/protocol.c`, with the
  existing build headers and `HAVE_FD_PASSING`; no package was installed.
- `python3 -B -m unittest discover -s tools -p '*_test.py'`: **147 passed,
  2 expected skips**.
- `sh tools/largefile_source_guards.sh`: **passed** with 597 capability
  entries, release-readiness controls, snapshot checks, acceptance schemas,
  and source guards.
- Focused controls passed: legacy clamd protocol **6/6**, FILDESREPORT
  protocol **1/1**, service oversize/health/cleanup **22/22**, service workload
  policy **28/28** with 2 Linux-only skips, and acceptance map **597/597**.
- Root and auxiliary status snapshots, regenerated Phase-0 inventory, and
  `git diff --check` passed.
- Two consecutive current source-manifest generations matched at:
  `1f16a6014a02be9857f41866926c15c39db282459d69baa9aaa3eb65923e4160`.

Disposition: development-verified implementation slice only. The available
Docker image does not contain JSON-C or Check development headers, so no linked
current-source C runtime claim is made. Certified Linux x86-64 execution,
full-size ingress/on-access service evidence, R03 runner qualification, R04
authoritative records, sanitizer evidence, and final release qualification
remain open. No capability status was promoted.

Follow-on transport hardening (2026-09-11 UTC): the fd-passing connect and
writable-send waits now rebuild their `fd_set` and remaining timeout after
each `EINTR`, preserving the absolute operation deadline. Linux-style
`MSG_NOSIGNAL` is used for raw command and descriptor sends, while platforms
providing `SO_NOSIGPIPE` configure it on the socket, so a daemon-side close is
reported as a write failure rather than terminating clamonacc. The focused
Docker syntax check again passed with `-Werror`; the host suite passed 147
tests with 2 expected skips; source guards, inventory/snapshot validation,
and `git diff --check` passed. The current source-manifest SHA-256 is
`3a29e00559104dd7328e4bd8e1bd264c38fc7f2e238cb3aafa2332433773a119`.
No capability was promoted.
