# Task receipt: R03 Sonic1 mounted-snapshot revalidation

Task ID / parent milestone: `R03` / `R10`

Purpose: determine whether the sole failure in the fresh Sonic1 27/28 CTest
run was only a stale generated inventory or a broader source-snapshot
divergence.

Environment:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Mounted source: `/tmp/clamav-32gb-current-20260915` at `/src`.
- Container image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.

Revalidation actions:

1. Synchronized the small `tools/largefile_inventory.sh` generator and
   `32gb-current-snapshot.md` over the authorized SFTP path.
2. Regenerated `/src/docs/largefile-inventory.tsv` from the mounted source.
3. Verified the generator hash now matches the local candidate:
   `f705cb1d8d70dba7f3c1af181cb0e5c90445215eb8df68f82e79ef4d7d339013`.

The exact local generator hash is
`f705cb1d8d70dba7f3c1af181cb0e5c90445215eb8df68f82e79ef4d7d339013`.
The mounted regenerated inventory was 45,422 lines with SHA-256
`8e6a4d0b89fc5fb82b5ca186bfdf46490429834fb5bff6bf6a491a99ed98f25c`.
The local candidate inventory is 45,585 lines with SHA-256
`a19d7e064a20926de7ee196e71d55b5b38127ab7510e6405a8f6c0e1d3c16e34`.

The mounted Git revision is `08b3ab820e40ac8bd307290b0c78c03c94884f1b`; the
local candidate tip is `dac92fa2`. The tracked asynchronous source-guard
rerun therefore reached the older source's own fanotify evidence tests and
failed with four stale-contract cases: the mounted
`largefile_fanotify_evidence.py` requires no `actor-result` artifact, while
the current local contract does. The command was:

```text
ctest --test-dir /src/build-roadmap-20260920 --output-on-failure \
  -R '^largefile_source_guards$'
exit=8
```

The result proves that regenerating one inventory is insufficient to make the
remote build a current-source candidate. No capability was promoted and no
large source transfer was retried after the existing durable-transfer policy
boundary. The local source guard remains passing.

Next action: obtain an authorized current-source Sonic1 snapshot/build, or
continue with independent local implementation work. Do not reuse this
mounted revision as current-candidate or release evidence.

State: `development-verified; stale-source-snapshot-blocked`
