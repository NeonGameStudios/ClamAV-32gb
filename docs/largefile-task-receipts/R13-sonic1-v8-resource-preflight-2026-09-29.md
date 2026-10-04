# R13 Sonic1 v8 resource preflight — 2026-09-29

## Scope

This is a read-only resource preflight for the current v8 source package, not
an accepted PCRE, fanotify, service, or release run. Host/profile:
`sonic1` / `sonic1-camera-key`. The pinned container is
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
with image ID
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
Its v8 source package SHA-256 is
`785494e0713a0e5a8cbef44a4f63dd5a7e36a61a6954e5b5e7262b383706bca3`,
and its regenerated source manifest SHA-256 is
`f71a59692fd63357ba6f1ff362275cfadddfd20f6f01ac8b3edc5cb9ec99e723`.

At `2026-09-29T09:22:02Z`, `free -k` on Sonic1 reported:

| Measure | KiB |
| --- | ---: |
| MemTotal | 65,234,456 |
| MemAvailable | 23,667,292 |
| Shared | 40,122,044 |
| Swap | 0 |

The same container reported `/qualification` as an ext4 mount with
21,446,639,616 bytes available, and its private `/dev/shm` as a 40-GiB tmpfs
with 41,081,544,704 bytes used and 1,868,128,256 bytes available. `docker
stats --no-stream` attributed 40.03 GiB memory to the pinned container.
Inspection of its `/dev/shm` directory found the fully allocated exact-32-GiB
OneNote fixture
`r12-v17-onenote32g-clamscan-diskspool-20260927-run01-input.one` (size
34,359,738,368 bytes, 67,108,864 512-byte blocks, inode 1619,
mtime 1790541183), plus three parked YaraCompiler build trees. Earlier
R12 receipts use this fixture; it is retained evidence, not disposable
scratch space. Neither the fixture nor the build trees were altered.

The source-bound v8 `tools/largefile_host_preflight.sh` was then invoked
inside that container with output directory
`/qualification/r13-v8-host-preflight-20260929T0923Z` and the certified
48-GiB threshold, `50331648` KiB. It exited 1 as expected and retained
`host-preflight.txt` (SHA-256
`0749f98d200939e73c8adfad2b02ce1ac40f5fb2fc27dcb89c37c884db53c550`).
At `2026-09-29T09:23:30Z` it reported effective available memory of
23,655,516 KiB, `available_memory_check=fail`, `cgroup_memory_limit_bytes=max`,
and 20,943,976 KiB available on `/qualification`. This is a fail-closed
preflight, not a failed scan or a passing qualification.

## Admission decision

The accepted v17 disk-backed exact-32-GiB PCRE proof peaked at 33,641,948
KiB process-tree RSS. Current available memory is 9,974,656 KiB below even
that observed peak, with no swap. Starting the equivalent current-source
full-subject PCRE scan would risk an OOM event and violate the acceptance
contract. The certified daemon/on-access profile separately requires at least
48 GiB effective available memory and 68 GiB free disk-backed temporary
space; both current measurements are below those floors. The existing pinned
container also has `Privileged=false` and no added capabilities, so it cannot
be used for real fanotify permission events. The v8 Release build does contain
`clamd` and `clamonacc`; the blocker is runtime admission, not missing binaries.

No full PCRE scan, fanotify run, lowered-limit substitute, volume resize,
tmpfs fixture deletion, software installation, or push was performed. An
earlier direct-RAM diagnostic already demonstrated an OOM kill with a 32-GiB
tmpfs subject plus the PCRE working set; see
`R13-sonic1-v17-pcre-phase-proof-2026-09-27.md`. This preflight must not be
counted as a failed current-source scan or a passing qualification case.

## Next action

Preserve or explicitly retire the valuable tmpfs fixture under user direction
before reclaiming its RAM. Provision enough disk-backed space for a recoverable
copy and the 68-GiB admission floor, or use another authorized runner meeting
the same contract. Then repeat the memory, disk, swap, mount and source-identity
preflight before current-source PCRE, service and privileged fanotify work.

State: `resource-preflight-blocked; candidate-v8-intact; release-gates-open`
