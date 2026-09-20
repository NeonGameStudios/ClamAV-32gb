# R03 Sonic1 container revalidation — 2026-09-20

## Scope

Revalidated whether the existing Sonic1 development container could provide a
current-source qualification path without another source transfer.

## Authoritative result

- Host: `sonic1` (`192.168.1.216`), login profile `sonic1-camera-key`.
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- `/src` is a read-write bind from `/tmp/clamav-32gb-current-20260915`.
- Remote `git rev-parse HEAD`: `08b3ab820e40ac8bd307b0c78c03c94884f1b`.
- Local qualification checkout: `3af4595e` (`Reject malformed XAR checksum digests`).
- Remote `git status --short` reports extensive modified tracked files and
  untracked build, target, fixture, provenance, and evidence payloads.

The remote container remains a stale, dirty development tree. Its source is
not revision-identical to the local candidate and cannot provide current-source
qualification evidence. No remote files, containers, processes, or transfers
were changed. No capability was promoted.

## Verification

The host list and connection description succeeded, Docker provenance matched
the explicitly supplied container identity, and read-only `git rev-parse` and
`git status --short` completed successfully through MCP-SSH. The earlier
durable current-source archive denial (`file_write_limit_exceeded`) remains the
external staging boundary; this revalidation did not retry it.
