# R13 Sonic1 v9 resource admission — 2026-09-29

This is a read-only/fail-closed preflight for the frozen v9 candidate, not
a failed full-size scan or accepted PCRE/service proof. Host/profile:
`sonic1` / `sonic1-camera-key`. Pinned container:
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The extracted v9 source manifest SHA-256 is
`884ba2f7a7e180a063c48bb62a8417e20277dee9c849c2f8e307bfdc50fb06b0`.

At `2026-09-29T11:45:59Z`, the source-bound
`tools/largefile_host_preflight.sh` wrote
`/qualification/r13-v9-host-preflight-20260929T1145Z/host-preflight.txt`,
SHA-256
`c9d10e047a2ba1bf8513da025bc66af1acd8f126cd29d59947fb273d61545b10`.
It exited 1 for the expected minimum-memory refusal, not a scan failure:

| Measure | Observed |
| --- | ---: |
| Physical memory | 65,234,456 KiB |
| Effective available memory | 23,666,220 KiB |
| Certified available-memory minimum | 50,331,648 KiB (48 GiB) |
| Cgroup limit | `max` |
| Qualification LV free, preflight `df -Pk` | 13,617,552 KiB |
| Qualification LV free, follow-up byte-precise `df` | 13,944,373,248 bytes |
| Host-root overlay free | 70,606,848 bytes |
| Swap | 0 |

The pinned container's private `/dev/shm` is 40 GiB and was using
41,081,544,704 bytes. Its retained OneNote fixture
`r12-v17-onenote32g-clamscan-diskspool-20260927-run01-input.one` still has
size 34,359,738,368 bytes, 67,108,864 allocated 512-byte blocks, inode
1619 and mtime 1790541183. It is prior test evidence and was not removed or
rewritten. The v17 disk-backed full-subject PCRE proof previously peaked at
33,641,948 KiB process-tree RSS; current available memory is below that
observed peak, with no swap. The certified service/on-access profile also
requires at least 68 GiB free disk-backed temporary space, far above the
current qualification LV free space.

No full PCRE scan, 32-GiB disk-spooled OneNote parse, certified service or
fanotify run was started. No LV was resized, fixture deleted, software
installed or usage reset used. After disk/memory provisioning is authorized,
repeat source, mount, memory, disk and swap preflight before those runs. Real
fanotify also requires a privileged runtime/mount; the current pinned
container is not by itself evidence of that capability. Production-CVD
canary prerequisites remain separately open.

State: `v9-resource-admission-failed-closed; full-pcre-service-onaccess-pending; candidate-intact`
