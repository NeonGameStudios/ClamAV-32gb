# R03 Sonic1 v15 release recheck after connectivity returned — 2026-09-27

## Scope and provenance

Sonic1 became reachable again through MCP-SSH with host `sonic1` and login
profile `sonic1-camera-key`. The live connection diagnostic passed policy,
TCP, host-key, authentication, profile authorization, and SFTP startup.

The retained clean v15 source manifest is
`e5b0d36e0ac086aed6c0d9fe7037ef0c3ba1fb9fd6f2b3ac38a14891c4e4b04f`,
from package SHA-256
`45d1e6e67647e5fb68a9c6e60db9d4331392af1b2725416aff978db74d56369c`,
transfer `transfer_78bfd4d3efcd4ecc9319ed16ee67748d`.
The scanner was the release build at
`/qualification/build-v15-e5b0d36e-release`, inside container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
with image ID
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The retained source was `/qualification/src-v15-e5b0d36e`.
Local and remote SHA-256 hashes matched for `libclamav/matcher.c`,
`libclamav/scanners.c`, and `unit_tests/check_clamav.c`. The local PCRE
evidence verifier has since changed and was not part of the remote v15 package.

## Test results

The tracked ordinary release suite job
`job_a2c47ba7b34e49bcb669ef88fbdeaf5f` ran CTest excluding the exact
32-GiB case with `TMPDIR` on the dedicated qualification volume. Thirty
tests passed. `libclamav_rust` failed before executing Rust tests because
the inherited `CARGO_HOME=/src/build` was on a read-only mount and Cargo
could not create its git cache directory. The isolated retry
`job_d52f2fb392a54e028de10c0db03aa47d` set
`CARGO_HOME=/build/cargo` and `CARGO_NET_OFFLINE=true`, used the existing
writable cache, and passed 1/1 in 0.29 seconds. Thus all 31 ordinary
release tests passed across the corrected tracked runs.

The exact-size case first rejected an invocation without its required
`CLAMAV_LARGEFILE_FIXTURE` path at startup. The corrected tracked job
`job_95008c0ca36e4f6ebd41e5e2a0e18d93` pointed it to
`/dev/shm/clamav32gb-edge-20260926.bin` and passed 1/1 in 345.73
seconds. That test independently requires a fully allocated exact
34,359,738,368-byte fixture, checks `SEEK_HOLE` and the final
`EDGE-LATE-MARKER`, then exercises file-path, descriptor, and fmap
library APIs with late detection and report assertions.

An initial 30-second MCP-SSH job deadline was too short for the ordinary
suite. The timed-out host job left the exact CTest child tree running in
Docker; the specific live PIDs were inspected and sent SIGTERM before the
properly tracked retry. No unrelated process was stopped.

## Qualification boundary

The host has swap disabled, but the dedicated qualification volume had only
about 52–53 GiB free during this recheck, below the roadmap's 68-GiB
disk-backed staging gate. The root filesystem had only about 272–280 MiB
free, so the tests used dedicated `/qualification` temporary storage.
The 32-GiB RAM fixture also leaves only about 29 GiB MemAvailable, too
little to start a second full-subject PCRE allocation safely. This recheck
does not promote PCRE, production-CVD/service, on-access, or final release
readiness.

No software was installed or downloaded, no GitHub workflow was changed
or triggered, and no commit or push was made.
