# R13 MCP-SSH async continuation receipt — 2026-09-16 UTC

## Scope

This is an MCP-SSH transport/orchestration receipt, not qualification
evidence. It records how a remote step that exceeds the short synchronous
command window is continued through an agent-owned tracked job.

## Reviewed identity

- host: Sonic1 (`sonic1`), Linux x86-64;
- login profile: `sonic1-camera-key`;
- source container: `clamav-current-source-20260915`;
- container ID:
  `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`;
- image ID:
  `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.

## Continuation result

`ssh_command_preview` with `operation="start"` admitted the source-guard
command with an effective timeout of 600 seconds. `ssh_command_start` then
created tracked job
`job_77f04678343545e3bb885a3064b8a0aa`, proving the async continuation path
is available past the synchronous command window. The job was polled with
`ssh_command_status` and reached a terminal failed state; it did not time out,
and no detached process was used.

The initial async result carried no output. A bounded diagnostic run against
the same healthy container reported the actual failure:

```text
large-file source guard failed: committed inventory is stale
```

The remote source bind is therefore an older/stale snapshot relative to the
current checkout. This receipt does not promote the remote run or any of its
outputs as source or qualification proof.

## Operational conclusion

Tracked async jobs extend one MCP request up to the host policy's effective
limit. Work requiring more than 600 seconds must be split into checkpointed,
bounded phases and each phase must retain its own real exit status. Large
source/evidence movement must use the MCP-SSH durable transfer APIs and be
reconciled after interruption.

State: `async-continuation-proven; remote-source-snapshot-stale`.

## Current policy recheck

A fresh `ssh_command_preview` for `operation="start"` on the same supplied
Sonic1 host/profile admitted a requested and effective timeout of 3600
seconds. The previously recorded 600-second value was therefore an earlier
effective limit, not a permanent MCP-SSH ceiling. The tracked async path can
be extended by requesting the larger value that the current preview admits;
the returned effective limit remains authoritative.

To avoid the denied client upload, an isolated server-side clone of the
already-pushed branch was attempted at `/tmp/clamav-32gb-remote-20260916`.
The tracked job `job_2256db0c07254aad88d918ed80803fc1` reached terminal exit
128. A bounded `git ls-remote` diagnostic reported:

```text
fatal: could not read Username for 'https://github.com': No such device or address
```

Sonic1 therefore lacks credentials for a server-side clone of this private
repository. The documented client-local durable upload handoff was also
rejected before transfer creation with `file_write_limit_exceeded`. No
alternate or untracked copy path was attempted, and the pre-existing remote
source container was left untouched.

## Follow-up freshness check

Using the same supplied host/profile, the bounded Docker inventory and
container provenance checks confirmed that the current container is still
running from bind source `/tmp/clamav-32gb-current-20260915`. Read-only
container checks returned committed source `08b3ab820e40ac8bd307290b0c78c03c94884f1b`
and a dirty tree containing unrelated generated artifacts. The local checkout
is at `6312634ec24539dc6087a76df401a81b8e9aca7c`, so the existing container
was not reused for current-source qualification and was left untouched.

## Fresh-source handoff attempt

The current checkout was packaged separately as an 18,610,167-byte archive
with SHA-256
`0a8abc82f48325d96642b24f5f126c06f551e9ccda4c30ef70c8b8b4024de583`.
`ssh_files_upload_start` was then requested for a new destination,
`/tmp/clamav-32gb-current-20260916.tar`, with the expected size and digest.
MCP-SSH rejected the request before opening a transfer with the authoritative
reason `file_write_limit_exceeded`; no remote file or transfer state was
created. The durable upload route is therefore documented, but the current
source cannot be staged until the Sonic1 policy permits another file write.

## Independent verifier invariant hardening

The kernel artifact verifier now requires exactly one `target: true` event in
each retained JSONL artifact, preventing an additional target-marked event
from being hidden beside the selected event ID. The actor verifier now
requires `actor_exit_code == 0` exactly when the actor observed an open,
binding the process result to the recorded permission outcome. Two negative
regression cases cover these contradictions. The focused evidence suite
passes 20/20; no qualification result was promoted.

## Fresh long-window lifecycle proof

On the same host/profile, a new `ssh_command_preview` for `operation="start"`
admitted a 60-second effective timeout. The tracked job
`job_44bb4e6069254e139c0212d940e0b76f` ran `sleep 25`, was observed as
`running` after the initial status poll, then reached `succeeded` with exit 0
after 25 seconds. `ssh_command_output` was called at offset 0 and returned
`eof=true` with zero bytes. This confirms that the continuation path itself
survives beyond the 20-second synchronous window; it made no Docker, source,
or filesystem changes.
