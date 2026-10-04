# R13 clean monitoring-only cleanup-grace follow-up

Date: 2026-09-26

## Scope and source state

This receipt records a development harness fix and its focused verification. It
does not qualify R13 or change any capability status.

- Repository: `ClamAV-32gb`, branch `largefile-roadmap-qualification`.
- HEAD: `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`.
- The working tree was already dirty before this follow-up. The recorded file
  hashes cover the complete current files, including earlier uncommitted work;
  they are not hashes of this one-line change alone.
- `tools/largefile_fanotify_runtime_runner.py` SHA-256:
  `f7e66983d1cbee57e4dc85603dc5d89a3aab918b22455c6d8cac8cc44ab6b551`.
- `tools/largefile_fanotify_runtime_runner_test.py` SHA-256:
  `fd1b6d02808ccdcb7494c961d6c195f2bff0246f767eb89ae4d8694dcc8c5b70`.

## Change and local evidence

The runtime runner's graceful SIGTERM wait in `stop_process` was increased
from 10 to 30 seconds. If the process still does not exit, the runner retains
its SIGKILL fallback and 10-second reap wait. A focused regression test asserts
that a cooperative daemon receives the 30-second grace and is not killed.

Verification on the current local working tree:

- `python3 tools/largefile_fanotify_runtime_runner_test.py`: 11 tests passed.
- `git diff --check`: passed.
- No build, full scan, commit, or push was performed for this follow-up.

## Related Sonic1 runtime evidence

The preceding diagnostic run is retained at
`/qualification/r13-report-consistency-fix-v3-20260925/runs/r13mg260926` on
Sonic1, with launcher and resource sidecars alongside it. It used the pinned
qualification container (`37c15f1f08b9325834e0dc487c09e6e0631c62275a9deb3e93654266cc042bb5`),
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`,
network disabled, the fully materialized 32-GiB fixture, clean official DB, and
a diagnostic-only 30-second SIGTERM cleanup override. The scan report was
`COMPLETE` and clean, with 34,359,738,368 logical bytes and successful daemon,
actor, socket/PID, and temporary-file cleanup. This run preceded the source
edit recorded above and is behavioral corroboration, not a run of the newly
hashed runner file and not a certified R13 capability result. It used a 32-GiB
temporary ceiling because disk headroom was below the release admission gate.

## Current admission and release status

At the latest Sonic1 read-only check, qualification storage had
72,117,112,832 bytes free (about 67.16 GiB), below the required 68 GiB
(73,014,444,032 bytes). `MemAvailable` was 65,266,163,712 bytes, and swap was
zero. A release-valid full R13 rerun was therefore not started.

The local readiness gate remains blocked: 604 capabilities total, 0 qualified,
147 bounded, 443 pending, 14 explicitly unsupported, 590 blocked, and 80 parser
blockers. The goal remains active; this receipt is not a release claim.
