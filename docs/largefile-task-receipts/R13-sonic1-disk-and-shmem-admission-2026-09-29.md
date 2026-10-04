# R13 Sonic1 disk and shared-memory admission diagnosis — 2026-09-29

This is read-only provisioning evidence, not a passed scan, PCRE proof,
service result, or authorization to reclaim retained files.

On `sonic1` with login profile `sonic1-camera-key`, `vgs --units b --nosuffix`
reported 535,600,037,888 bytes unallocated in `ubuntu-vg`. The dedicated
`clamav_qualification_v1` ext4 LV is mounted at
`/tmp/clamav-qualification-disk-lv-v1`. After the v12 case-bundle test,
`df -B1` reported 5,471,596,544 bytes available there, far below the
68-GiB disk-backed admission minimum. The host root ext4 filesystem is
separately almost full and must not be treated as staging headroom. Existing
`lvextend` and `resize2fs` executables were found; no software install is
needed for a possible dedicated-LV expansion.

`free -b` reported 66,800,082,944 bytes physical RAM, 24,242,929,664 bytes
available and zero swap. This is below the required 48-GiB effective
available-memory minimum. The pinned container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
reported 41,081,544,704 bytes used in its private 40-GiB `/dev/shm` mount;
its cgroup `memory.stat` attributed the same amount to `shmem`, and
`memory.events` remained `oom=0`, `oom_kill=0`. Read-only `du -sh` showed:

| Private `/dev/shm` entry | Approximate usage |
| --- | ---: |
| `r12-v17-onenote32g-clamscan-diskspool-20260927-run01-input.one` | 32 GiB |
| `build-yc-stream-v4-20260929-asan-parked` | 3.9 GiB |
| `build-yc-stream-v4-20260929-release-parked` | 1.2 GiB |
| `build-yc-stream-v5-20260929-release-parked` | 1.3 GiB |

The container's `/ram` bind source is **not** this tmpfs: host `findmnt`
resolves it to the nearly full root ext4 filesystem. Therefore the earlier
description of `/ram` as a RAM-backed copy was incorrect. Do not retire the
read-only `/ram/edge-stable.bin` fixture on that premise.

Potential next steps require separate user authorization: extend only the
dedicated qualification LV using unallocated `ubuntu-vg` extents. The
initial proposal to copy the OneNote tmpfs fixture to disk and then remove
it is superseded by the integrity mismatch documented below; that fixture
must be preserved pending investigation and a verified replacement.
The three parked build trees remain untouched unless separately authorized.
The original v17 OneNote fixture and prior evidence are retained as-is.

## 2026-09-29 17:39–17:46 UTC recheck: retained fixture hash mismatch

The same pinned container remained running. The dedicated LV had
2,217,680,896 bytes available, and host `MemAvailable` was 24,197,955,584
bytes with zero swap. The retained OneNote fixture still reported size
34,359,738,368 bytes, 67,108,864 allocated 512-byte blocks, inode 1619,
mtime 1790541183, and ctime 2026-09-27 20:33:03 UTC. A bounded read still
found `MZP` at offset 34,359,719,413. `fuser -v` reported no open users at
that point in time only.

However, a fresh full-file GNU `sha256sum` in managed job
`job_97cbd2cbc2f642eaa814993f0f917c6f` returned
`cb3ea750b0e9d9095d80731c676045823405a4d3b7b50bd52304476e56ec8a78`.
An independent Python `hashlib.file_digest` in managed job
`job_71a5b30327214774a810ce2f0d8fab81` returned the **same** digest.
Earlier R12 v3/v4/v6 receipts recorded several independent full-file and
scanner hashes of this same filename as
`1c593530684ac8c98d818437db669e556966051e4b1c4b4e9a65c049623feacf`.
An independent local reconstruction from the repository's 52,297-byte
`clam.exe.webapp-export.one.xor` source (decoded with the repository's XOR
key), the fixture generator's 108-byte original prefix, 16-byte inserted
prefix, 34,359,686,054 zero payload bytes, one-byte element terminator,
and remaining original source bytes reproduced **that prior digest exactly**.
The reconstructed first 64 bytes also matched the current remote file.
A source-bound remote comparison in managed job
`job_2909466f2beb4ce7b929566917e59477` found that the full 124-byte
header/framing and 52,190-byte terminator/original-source suffix still
match. A complete read-only sweep of the intended zero payload in managed
job `job_1aba8d0cb49a41be8e25e25c1e7ae636` found exactly **one**
nonzero byte: value `01` at absolute file offset 17,617,552,487, where
the generator wrote `00`. Thus the present bytes differ from the expected
fixture by one bit, despite unchanged metadata and the late marker. The
mechanism of that bit change is unknown; no in-place repair was attempted.
Matching size/inode/timestamps and one marker are insufficient to treat the
current bytes as the prior qualified input. The current fixture must not be
reused as the prior input oracle, migrated as a verified copy of the prior
input, or deleted to reclaim RAM until its provenance is resolved. No
fixture or volume was changed by this recheck.

State: `admission-prerequisites-identified; retained-fixture-integrity-mismatch; host-layout-and-fixtures-unchanged`

## 2026-09-29 post-v16 capacity recheck and proposed sizing

No volume or fixture was changed. After a source-bound v16 development build,
the dedicated LV had only 242,446,336 bytes available. The container root
overlay had about 6.9 MiB free, so all new test temporary files must avoid
it. A guarded ordinary unit-suite run was stopped at its dedicated-LV
300-MiB floor; see
`R08-sonic1-v16-unrecorded-vds-2026-09-29.md` for the retained partial logs.
Host `free -b` reported 24,191,098,880 bytes available and zero swap, still
below the 48-GiB admission threshold. `vgs` reported 498.82 GiB free in
`ubuntu-vg`, without modifying it.

The earlier 128-GiB extension idea is too small if we preserve the current
32-GiB mismatched tmpfs file as a **quarantined, checksum-identified artifact**
on disk, retain fresh exact-32-GiB and 32-GiB-plus-one materialized fixtures,
and still require 68 GiB of free disk-backed staging. At the present free
space, a **192-GiB** extension of only `clamav_qualification_v1` would leave
approximately 96.2 GiB free after those three 32-GiB-scale copies, about
28.2 GiB above the staging floor before filesystem metadata and further
evidence growth. Recheck actual free bytes after every copy; this arithmetic
does not itself prove admission. The mismatched file must never be relabeled
as the earlier verified oracle. Moving it off tmpfs and reclaiming its RAM
also requires explicit user approval and independently verified source and
destination hashes. Available memory must be measured again afterward;
64 GiB physical RAM does not by itself establish 48 GiB effective headroom.

State: `bounded-development-passed; capacity-and-memory-admission-await-explicit-authorization`
