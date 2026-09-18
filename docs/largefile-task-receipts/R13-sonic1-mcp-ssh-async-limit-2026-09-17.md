# R13 Sonic1 MCP-SSH async limit recheck — 2026-09-17

## Scope

Recheck the documented MCP-SSH continuation procedure on the assigned Sonic1
host and determine whether a tracked job can be extended beyond the currently
recorded asynchronous limit. This is transport/orchestration evidence only;
it does not modify the source tree, Docker containers, or qualification
status.

## Identity and preview

- Host: `sonic1`
- Login profile: `sonic1-camera-key`
- `ssh_connection_describe`: succeeded; POSIX host, sudo-enabled command path,
  SFTP identity `camera`.
- `ssh_command_preview` with `operation="start"`, command `docker ps
  --format {{.Names}}`, requested timeout `86400`, and
  `timeout_mode="use_effective_limit"`: allowed.
- Returned effective limit: `3600` seconds.
- The preview returned `requested_timeout_seconds=86400` and
  `effective_timeout_seconds=3600`; the policy therefore clamps an oversized
  request rather than extending the job beyond one hour.
- Matched policy: `simple-full-access-async-sudo-sonic1-sonic1-camera`.

## Tracked lifecycle proof

The exact `ssh_command_start` path was then exercised with a harmless tracked
`sleep 25` job, requesting `86400` seconds with the same effective-limit
mode:

- Job: `job_c113f6f0837f4cc4922a20c19676f644`
- Start response: `status=ok`, `remote_started=true`, `state=running`,
  `effective_timeout_seconds=3600`.
- Mid-run `ssh_command_status`: `state=running`, with no exit code yet.
- Terminal `ssh_command_status`: `state=succeeded`, exit code `0`, elapsed
  remote lifetime `25` seconds.
- `ssh_command_output` from offset `0`: empty stdout with `eof=true` and
  `next_offset=0`.

## Conclusion

The documented async path is usable and extends beyond the short synchronous
command window. No supported MCP-SSH option was found that authorizes a
single job past the policy's current 3600-second effective limit. Longer
roadmap phases must be split into tracked bounded phases, with each job
polled and reconciled before the next phase. No remote source, container,
filesystem, or qualification evidence was changed or promoted.

## Next action

Continue local implementation and testing while the current-source delivery
and Sonic1 disk-backed temporary-space prerequisites remain unresolved. Do
not use a detached remote process or retry the denied durable source upload
through alternate paths.

## Fresh transport recheck

After the local guard-wrapper verification completed, the documented
`ssh_command_start` path was retried for a read-only `docker ps -a` probe with
the same host/profile and a 60-second requested timeout. The request matched
the configured async-sudo rule but failed during SSH connect after 30 seconds
with `remote_started=false` and `retryable=true`. No remote command, Docker
container, source file, or job was created. This confirms that the documented
async extension can outlive the synchronous request window when the host is
reachable, but it cannot bypass a current Sonic1 connection failure.

## Fresh connection diagnostic

The side-effect-free `ssh_connection_check` was run with the same host and
profile after the tracked command retry. Policy evaluation and address
resolution passed (`1 address(es)`), but the TCP-connect phase timed out at its
fixed `timeout_seconds=20`. The diagnostic reported `overall=failed`,
`remote_started=false`, and `retryable=true`; authentication and SFTP phases
were not reached. This is a transport reachability failure before async job
creation, not a workload-duration limit.
