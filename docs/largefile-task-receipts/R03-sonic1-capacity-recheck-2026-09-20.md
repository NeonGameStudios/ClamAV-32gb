# Task receipt: R03 Sonic1 capacity recheck

Task ID / parent milestone: `R03` / `R13`

Scope: recheck the current Sonic1 Linux x86-64 admission envelope before
launching another full-size qualification workload. This is host evidence,
not a qualification result.

Environment and identity:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Source bind: `/tmp/clamav-32gb-current-20260915` mounted at `/src`.

Command and result:

```text
sh /src/tools/largefile_host_preflight.sh /tmp/clamav-preflight-20260920 50331648
exit=0
```

- Kernel: Linux 5.15 x86-64; 12 CPUs.
- `memory_total_kb=65234456`.
- `effective_memory_available_kb=62097272`.
- The 48-GiB minimum (`50331648` KiB) passed; the cgroup memory limit was
  unlimited.
- Disk-backed `/tmp` reported `32809292` KiB available. The roadmap requires
  at least 68 GiB (`71303168` KiB) free before the certified full-size run.
  Temporary-space admission therefore remains blocked.

Read-only inventory:

- `/tmp/clamav-materialized-edge-20260909`: approximately 33 GiB.
- `/tmp/clamav-32gb-current-20260915`: approximately 34 GiB.
- These retained trees contain audit fixtures, evidence and the current
  disposable source mount. Neither was deleted or repurposed; cleanup needs
  an explicit target/retention decision.

Next action:

- Obtain additional disk-backed temporary capacity or an explicit cleanup
  decision for retained disposable evidence, then rerun the preflight before
  any 32-GiB materialized qualification workload.
- Fanotify permission-event qualification remains separately dependent on a
  real authorized kernel capability; this receipt does not waive that gate.

State: `runner-preflight-partial; temporary-space-blocked`
