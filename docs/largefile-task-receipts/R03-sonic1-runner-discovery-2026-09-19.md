# R03 Sonic1 runner discovery receipt — 2026-09-19

## Scope

This receipt records the authorized Sonic1 runner discovery slice for R03. It
does not claim a current-source build or qualification run.

Access used the supplied `sonic1-camera-key` login profile. MCP-SSH host
discovery returned host id `sonic1`; connection description confirmed an
x86-64 POSIX host, sudo-enabled command execution, and camera as the SFTP
identity.

## Host evidence

Read-only commands completed successfully:

```
uname -a
Linux sonic1 5.15.0-190-generic #200-Ubuntu SMP Fri Aug 7 15:06:04 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux

getconf _NPROCESSORS_ONLN
12

free -b
Mem: 66800082944 total, 63935778816 available
Swap: 8589930496 total, 7623667712 free

docker version --format '{{.Server.Version}}'
29.1.3
```

The active Docker/root filesystem is `/dev/mapper/ubuntu--vg-ubuntu--lv`,
with 316,464,824,320 bytes total and 57,167,597,568 bytes available. The
roadmap admission requirement is at least 68 GiB of free disk-backed temporary
space, so the active filesystem is short of the requirement.

Block-device inspection found a 1,024,209,543,168-byte NVMe device and an
`ubuntu-vg` volume group with approximately 698,808,795,136 bytes free. The
only current logical volume is the 322,122,547,200-byte root volume; no
separate `/mnt` or other mounted qualification volume exists. Extending the
root logical volume or creating and mounting a new one would be a host storage
mutation and was not attempted.

## Existing container boundary

Docker has an existing running container `53f6ca8d4a29` named
`clamav-current-source-20260915`. Its inspected provenance is:

- image id `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- working directory `/src`
- read-write source mount `/tmp/clamav-32gb-current-20260915:/src`
- running state at inspection time

The mounted checkout is stale and unsuitable as current-source evidence: it is
on `master` at `08b3ab820e40ac8bd307290b0c78c03c94884f1b`, has tracked changes
and untracked build/test artifacts, and its `rustc` invocation attempted an
unauthorized rustup sync then failed with permission denied. It was not
modified or reused for qualification.

The container has CMake 3.25.1 and Debian glibc 2.36. The installed Rust
command is not a usable pinned toolchain in that container; R03 still requires
the exact coherent Rust toolchain and current source.

## State and next action

State: **development-discovered; qualification blocked**.

The host architecture, CPU, memory, and Docker prerequisites are present. The
next authorized action is to provision at least 68 GiB free disk-backed space
on Sonic1 (using the unallocated volume-group capacity or another approved
volume), then transfer or obtain the immutable current candidate and configure
the pinned C/Rust Release build. The existing dirty container must remain
outside the evidence chain.

No host storage mutation, current-source upload, GitHub workflow, or usage-reset
credit was used for this discovery.
