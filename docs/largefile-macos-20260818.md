# Local macOS large-file validation

Date: 2026-08-18

## First preflight

The new macOS validation tools are:

```text
tools/largefile_macos_host_preflight.sh
tools/largefile_macos_runtime_gate.sh
```

The runtime gate is deliberately fail-closed. It requires 48 GiB of
reclaimable/available memory by default, generates sparse 32 GiB boundary
fixtures only after that admission check, and records macOS `/usr/bin/time -l`
resource data, marker offsets, temporary storage, and the 32 GiB+1 policy
result. Exploratory runs can lower the threshold with
`CLAMAV_MACOS_MIN_AVAILABLE_KB=0`, but that is not release evidence.

The preflight observed:

| Field | Observation |
|---|---|
| OS / architecture | Darwin 25.5 / arm64 |
| CPU | 8 logical/physical; 4 performance and 4 efficiency cores |
| Memory exposed to this execution context | 16 GiB (`17179869184` bytes) |
| Reclaimable memory at capture | approximately 3.2–3.8 GiB |
| Swap | 3 GiB configured; approximately 2.1 GiB used |
| Data-volume free space | approximately 4.8 GiB |
| CMake / Ninja | not installed |
| Available compiler/build tools | Apple Clang 21, GNU Make 3.81, Rust 1.97.1 |

The default runtime gate therefore stopped before generating or scanning the
32 GiB corpus:

```text
available_memory_check=fail
minimum_available_kb=50331648
```

This is an environment blocker, not a scanner result. The user-described
64 GiB bare-metal profile still needs to be reconciled with the 16 GiB memory
capacity visible to this macOS execution context. No software was installed.

## Remaining work

1. Confirm that the intended test process has access to the full 64 GiB host,
   rather than a 16 GiB VM, sandbox, or memory-limited execution context.
2. Provide or build a macOS `clamscan` binary once CMake/build dependencies are
   available through an approved existing toolchain.
3. Rerun `largefile_macos_runtime_gate.sh` with the default 48 GiB admission
   floor, then preserve its complete evidence directory in the release
   artifact rather than the source tree.
