# R03 Sonic1 current-candidate staging boundary — 2026-09-20

## Scope

Attempt to stage the clean current candidate `8da0127b` on the authorized
Sonic1 runner so the roadmap's current-source configure/build evidence can
continue. This receipt records a staging boundary only; no capability was
promoted and no qualification or release claim is made.

## Candidate identity

- local checkout: `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- branch: `largefile-roadmap-qualification`
- commit: `8da0127bd7eb4a8a73de777bf3675ac5a0068ce2`
- worktree: clean
- archive: `/private/tmp/clamav-32gb-8da0127b.tar.gz`
- archive bytes: `18,405,433`
- archive SHA-256: `f15d1bb1510b53c5e6868e68f21a8625f26f554704c299f79afa0cb77f609dfe`
- source manifest: `/private/tmp/clamav-source-manifest-8da0127b.txt`
- source manifest rows: `1,710`
- source manifest SHA-256: `f7def859347ea1473e8d52014fb78a61765b5e8a77ee54673dc2427a436a5`

## Runner identity

- host: `sonic1`
- login profile: `sonic1-camera-key`
- container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`
- image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- `/src` bind: `/tmp/clamav-32gb-current-20260915`, read-write
- remote source: stale and dirty; it is not the candidate above

## Staging attempt

The documented durable `ssh_files_upload_start` handoff was requested with
destination `/tmp/clamav-32gb-current-8da0127b.tar.gz`, the exact archive
size and SHA-256, and the supplied Sonic1 profile. MCP-SSH denied the request
before opening a transfer:

```text
status: denied
reason: file_write_limit_exceeded
request: req_7bae5f635a254c0fbfaa5d734ef295c1
```

No remote file was written, no existing transfer was changed, and no
alternate destination, manual chunking, or untracked copy was attempted.
Read-only container inventory confirmed that no current-candidate source
directory is present in the existing container.

## State and next action

State: `staging-blocked-external`.

The current candidate remains locally available and independently checksummed.
The existing Sonic1 `/src` tree remains usable only for explicitly labelled
stale-source development diagnostics. Continue independent local checks and
implementation work; resume current-source Sonic1 qualification only after
the MCP-SSH file-write policy or an authorized runner changes.

No software was installed, no reset credit was used, and no capability status
changed.
