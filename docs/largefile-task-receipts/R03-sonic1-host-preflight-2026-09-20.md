# Sonic1 host preflight — 2026-09-20

The repository host-preflight script passed on the authorized Sonic1 container
before sanitizer planning. Evidence was written remotely to
`/tmp/clamav-7f3458c4-preflight/host-preflight.txt`.

## Identity

- Host: `sonic1`
- Login profile: `sonic1-camera-key`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Source bind: `/tmp/clamav-32gb-7f3458c4` mounted at `/src`
- Preflight UTC: `2026-09-20T00:12:49Z`

## Captured result

```text
kernel=Linux b46fa02bc4f4 5.15.0-190-generic #200-Ubuntu SMP Fri Aug 7 15:06:04 UTC 2026 x86_64 GNU/Linux
arch=x86_64
memory_total_kb=65234456
memory_available_kb=62282008
effective_memory_available_kb=62282008
minimum_available_kb=50331648
available_memory_check=pass
cgroup_memory_limit_bytes=max
cgroup_memory_current_bytes=3431436288
cgroup_limit_finite=no
cpu_count=12
filesystem_available_1024_blocks=37088712
filesystem_capacity=88%
cmake_version=cmake version 3.25.1
cargo_version=cargo 1.97.1 (c980f4866 2026-06-30)
gcc_version=gcc (Debian 12.2.0-14+deb12u1) 12.2.0
clang_path=missing
file_path=missing
```

The runner meets the memory preflight but cannot satisfy the sanitizer
toolchain contract without an external toolchain change. No installation or
download was attempted.
