# R03/R11 materialized-edge capacity check (2026-09-13)

## Result

The current host and existing Docker container cannot safely execute the
roadmap's materialized 32-GiB edge workload:

- host worktree volume: 477 GiB total, 442 GiB used, 35 GiB available;
- container `/src` mount: 229 GiB total, 216 GiB used, 13 GiB available;
- container overlay filesystem: 142 GiB total, 136 GiB used, 0 bytes
  available;
- container memory: 2.4 GiB total, 1.8 GiB available;
- container swap: 2.0 GiB total, 204 MiB already used;
- container architecture: `aarch64`;
- Docker contexts: only local `default` and `desktop-linux`; no Linux
  x86-64 context is configured.

The roadmap requires a certified Linux x86-64 runner with at least 48 GiB
effective memory and 68 GiB free disk-backed temporary space. Creating a
32-GiB materialized fixture here would exceed the available worktree and
container capacity and would not provide certified architecture evidence.
No fixture or large workload was created.

## Boundary

This is a concrete environment blocker for R03/R05/R11–R14 full-size,
materialized, resource, and production qualification. It does not invalidate
the current ARM64 development build or its passing unit/CTest evidence. An
authorized x86-64 runner with the required memory, temporary storage,
privileges, databases, and optional backends remains required.
