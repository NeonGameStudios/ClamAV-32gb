# R02/R04/R10 Sonic1 v10 private service admission — 2026-09-29

Task IDs: R02/R04/R10. This is a failed-start diagnostic and local harness
correction, not a completed daemon/client case or release qualification.

## Source-bound attempts

Host/profile: `sonic1` / `sonic1-camera-key`. Pinned container:
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`,
image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
The frozen v10 Git-less source manifest SHA-256 was
`a8bcd93903525147ababd91633e6764e570136ff4239332cb73c60d3e62a3d6a`.
The copied build's Release `clamd`, `clamdscan`, and CMake cache were verified
against SHA-256 values
`1daf216feaf3b7b097087887ccda8acafa944b95af06036c694288b641f29a91`,
`99a325973d7074d63f30feedbceb00c8744bdc0bdf93e438008100ba9dab0d70`,
and `0fc3d24b3f10929cbff0cb299d155decbf815f4e4ff5b8b7efedf21ac2e4beb1`.
The container's `/src` mount is stale and was not used. Both attempts ran the
v10 `largefile_development_service_capture.py` with its private TMPDIR on
the disk-backed `/qualification` volume, the v10 Release binaries, and the
v10 extracted source root. No daemon scan case ran because startup failed.

The first unique evidence root,
`/qualification/r02-r04-r10-v10-service-20260929-release`, is preserved.
Managed job `job_8599b322d34f4ec0a106ebd85df53d8c` exited 1 before
readiness. Its `logs/clamd-detection.log` SHA-256 is
`5f86228bd7437dd920a96e18c86aecba51f054b66757895c059fb7608fd8873b`.
The log reports `Cannot set socket permission` on its private Unix socket.
The generated socket pathname was 115 bytes, exceeding Linux's 107-byte
usable `sockaddr_un.sun_path` length: the bind path was truncated, and the
following chmod used the full pathname. The harness removed the private
temporary socket directory; no acceptance-record file was produced.

The second unique root, `/qualification/r02-v10-svc-20260929`, is also
preserved. Its predicted longest socket pathname was only 95 bytes, so it
does not reproduce the first error. Managed job
`job_7381b774b18143f0bc56baa3ab0d79ea` nevertheless exited 1 before
readiness because v10 `clamd` enforced its real admission gate:

```text
available_memory=24164429824 bytes is below required=51539607552 bytes
```

The second daemon log SHA-256 is
`7c7327a123d3cf2466744a5e79b87f1fd25562957e37324900094f3ae95b56ea`.
Its private temporary socket directory was empty afterward and it produced
no acceptance records. This is the expected resource refusal, not a failed
clean/detection/limit scan. The 64-GiB host had 65,234,456 KiB total,
23,635,116 KiB available, 40,122,104 KiB shared, and no swap on the
postflight. `/qualification` had 7,389,171,712 bytes free, separately below
the 68-GiB certified disk-backed staging floor. The pinned container's
`/dev/shm` used 41,081,544,704 bytes. Its previously retained exact-32-GiB
OneNote fixture remained unchanged: size/allocation 34,359,738,368 bytes,
inode 1619, mtime_ns 1790541183353212702. It was not moved or removed.

## Local harness correction and boundary

The development harness now uses a shorter `r04-` temporary-directory
prefix and checks the encoded AF_UNIX socket pathname before launching
`clamd`. An overlong path fails with an explicit shorter-TMPDIR diagnostic
instead of a confusing daemon chmod error. The local regression verifies the
Linux 107/108-byte boundary and that an overlong path never launches a
daemon. `PYTHONPATH=tools python3 -B -m unittest -v
tools.largefile_development_service_capture_test` passed 9/9, and
`sh tools/largefile_source_guards.sh` exited 0. This harness source change
postdates the frozen v10 package and has **not** been represented as a v10
remote pass.

No admission threshold was lowered, no tmpfs fixture was deleted or moved,
no volume was resized, no software installed, and no usage reset or GitHub
push occurred. The next full service/PCRE step requires authorized resource
provisioning and a new source-bound candidate, then a fresh admission
preflight. The current pinned container also lacks the privilege needed for
real fanotify permission events. No capability status was promoted.

State: `v10-service-start-refused-by-real-memory-admission; socket-path-harness-fixed-locally; release-gates-open`
