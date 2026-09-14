# R03 Sonic3 MCP-SSH connectivity check (2026-09-13)

## Discovery and policy

The configured host discovery returned the exact host ID `sonic3`. The
user-provided login profile `sonic3-sudo` was accepted by
`ssh.connection.describe`; it reports a POSIX host, sudo-enabled command
identity, and no configured workspace. A non-mutating preview of the exact
Docker inspection also returned `decision=allow` with the matched policy
`simple-full-access-no-restrictions-sonic3-alias-sonic3-sudo`.

## Live result

The exact read-only command was attempted twice:

```text
host=sonic3
login_profile=sonic3-sudo
command=docker
args=[ps, -a]
```

All three attempts timed out during the SSH `Connect` phase. The first used a
20-second timeout and the two retries used 30 seconds each. All three reported
`remote_started=false`; no remote command or Docker operation began. The
connection diagnostic itself returned a policy-layer
`no_matching_allow_rule`, while the command preview was explicitly allowed;
the live command failures are therefore recorded as connection timeouts, not
as successful or partially started remote work.

No source transfer, container mutation, build, test, or remote filesystem
write was performed through MCP-SSH.

## Boundary

Sonic3 remote qualification remains blocked by SSH connectivity from the
current MCP-SSH deployment. This is separate from the local ARM64/container
capacity blocker documented in the R03/R11 materialized-edge receipt.
