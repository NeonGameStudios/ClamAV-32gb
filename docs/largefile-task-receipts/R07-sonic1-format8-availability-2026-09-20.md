# R07 Sonic1 format-8 availability audit — 2026-09-20

Task ID / parent milestone: `R07` / `R03`

## Scope

Recheck the authorized Sonic1 runner for an already-installed compatible
format-8 bytecode compiler or an independently compiled format-8 artifact.
The roadmap permits this inventory without installing, downloading, or
transferring software. It is a prerequisite check only; it does not claim
format-8 qualification.

## Environment and access

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Connection description: Linux POSIX host `192.168.1.216:4456`, login user
  `camera`, sudo-enabled command path.
- Host inventory was refreshed through MCP-SSH before the checks.
- No Docker execution was needed for this inventory; the existing Docker
  containers remain stale-source candidates and are not treated as current
  qualification builds.

## Read-only checks

The following typed host commands were run with a 20-second effective limit:

```text
which clang       -> exit 1, no output
which gcc         -> exit 1, no output
which clambc      -> exit 1, no output
which llvm-link   -> exit 1, no output
which python3     -> exit 0, /usr/bin/python3
```

A bounded search of `/tmp` found repository source copies and bytecode API
sources, but no independently identified `.cbc`, `.bc`, `.ll`, or format-8
module. The only bytecode-related runtime already known on Sonic1 is the
previous `clambc` smoke from the stale source container, which reported that
LLVM was not compiled or linked.

## Result and next action

The R07 external prerequisite remains blocked: Sonic1 currently has neither
an authorized compatible format-8 compiler nor an independently compiled
format-8 artifact with source identity and hash. No software was installed or
downloaded, no transfer was retried, and no capability was promoted.

State: `blocked-external-prerequisite`
