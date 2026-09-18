# R03 Sonic1 provenance and capacity recheck — 2026-09-17

## Read-only evidence

- Host/profile: `sonic1` / `sonic1-camera-key`
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`
- Image: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53aa44cb9ba725a3a12d86df`
- Source bind: `/tmp/clamav-32gb-current-20260915` → `/src`
- Remote source commit: `08b3ab820e40ac8bd3072b0c78c03c94884f1b`
- Remote worktree: dirty with unrelated generated/build artifacts
- Current local checkout: `6312634ec24539dc6087a76df401a81b8e9aca7c`
- Container overlay available: `55,825,768` KiB

## Decision

The container is not a current-source candidate and is below the roadmap's
68 GiB disk-backed temporary-space requirement (`73,014,444,032` bytes). It
was not used for build or qualification evidence, and no remote files were
changed.
