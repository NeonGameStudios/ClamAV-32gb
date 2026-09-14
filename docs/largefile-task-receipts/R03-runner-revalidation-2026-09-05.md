# Task receipt: R03 Sonic1 runner revalidation

Task ID / parent milestone: `R03` / `R11`

Exact prerequisite: an authorized Linux x86-64 runner for the current
`largefile-roadmap-qualification` candidate.

Starting identity:

- Canonical local source: `<repository-root>`
- Branch: `largefile-roadmap-qualification`
- Local worktree remains dirty; no remote source mutation was attempted.
- Host/profile selected from the existing operator record: `sonic1` /
  `<redacted-login-profile>`.

Prerequisites verified:

- remote SSH host discovery returned `sonic1` as a POSIX host with the recorded
  full-access-sudo label.
- `ssh.connection.describe` succeeded for `<redacted-login-profile>`; it reported
  host `<redacted-private-address>:4456`, login identity <redacted>, pinned profile
  authorization, and sudo capability.

Observed failing prerequisite:

- `ssh.connection_check(host=sonic1, login_profile=<redacted-login-profile>,
  timeout_mode=use_effective_limit, timeout_seconds=30)` returned request
  `<redacted-request-id>`.
- Policy and address resolution passed, but TCP connect timed out after the
  effective 20-second limit. SSH authentication, SFTP and sudo were not
  reached; the check reported `remote_started=false` and
  `remote_may_still_be_running=false`.
- A bounded retry after the local OLE2 slice used the same authorized
  host/profile with `timeout_seconds=20` and returned request
  `<redacted-request-id>`. Policy and address resolution again
  passed, while TCP connect timed out at 20 seconds; the remote was not
  started and no SSH/authentication/SFTP phase was reached. A malformed
  diagnostic request using the unsupported `timeout_mode=default` was not
  treated as evidence.
- A current-state retry using the same host/profile and
  `timeout_mode=use_effective_limit timeout_seconds=30` returned request
  `<redacted-request-id>`. Policy and address resolution
  passed, while the effective 20-second TCP connect again timed out;
  `remote_started=false` and `remote_may_still_be_running=false`.

Changes made: none to the remote host or source candidate. This receipt only
records the current external prerequisite state so a later retry can be
compared against an authoritative result.

Development verification retained locally:

- ARM64 current-source `check_clamav` target rebuilt successfully in the
  disposable toolchain container after the latest fixture corrections.
- Local source guards and acceptance-map/schema checks pass, but they are not
  substitutes for the certified x86-64 build.

Remaining failures / next action: retry the same Sonic1 connection check after
the host/network is restored, or use an explicitly authorized equivalent
x86-64 runner. Do not claim R03/R11 qualification from the ARM64 build or
historical remote evidence.

State: `blocked-by-external-runner`; independent local R08/R10 development
work remains authorized and open.
