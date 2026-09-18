# R03 local toolchain image recheck — 2026-09-17

Task ID / parent milestone: R03 build readiness.

Exact capability kind:id list: application build prerequisite; no capability
status was changed.

Starting source identity: branch `largefile-roadmap-qualification`, local HEAD
`6312634ec24539dc6087a76df401a81b8e9aca7c`, intentionally dirty working tree.

Prerequisites verified: no software installation, image pull, source upload,
usage reset, commit, push, or GitHub workflow action was performed.

Existing images inspected read-only: `clamav-largefile-local-toolchain2:latest`
(image ID `3113a9a07ae4`) and `clamav-largefile-local-toolchain:latest`
(image ID `ffd69495e52c`). Both expose CMake 3.25.1 and `/usr/bin/cc`.

Commands and results:

* Each image was run with the current checkout mounted read-only at `/src`.
  `pkg-config` reported no `json-c`, `libcurl`, or `openssl` development
  package metadata in either image.
* Header inspection found `/usr/include/openssl/ssl.h`, but no
  `/usr/include/json-c/json.h` or `/usr/include/curl/curl.h`.
* A filesystem search found no prebuilt `clamscan` or `check_clamav` artifact
  inside the toolchain image.

Interpretation: these images cannot provide a coherent current-source
application build or linked C regression run. This confirms, rather than
resolves, the existing missing-dependency blocker; no dependency was disabled
or replaced with a stub for a build claim.

Next action: use an authorized runner or existing image with JSON-C, curl, and
complete OpenSSL development metadata, then build the current source with
application targets enabled. Sonic1 current-source delivery and disk-backed
temporary capacity remain separate external prerequisites.

State: blocked-prerequisite; runtime-qualification-open

## Sonic1 async capacity recheck

The documented MCP-SSH continuation path was exercised read-only with the
administrator-supplied `sonic1-camera-key` profile. A preview and tracked
`ssh_command_start` admitted the full effective async limit of 3,600 seconds;
the job was polled to terminal state and its bounded output was retrieved by
offset. Therefore the short synchronous command window is not the current
remote-build blocker.

The resulting `df -B1 -P` inventory showed the root filesystem and both
Docker overlay mounts with 57,165,213,696 bytes available. `/dev/shm` had
33,400,041,472 bytes available. No disk-backed mount reached the roadmap's
approximately 68-GiB staging prerequisite. The existing
`/tmp/clamav-32gb-current-20260915` source directory is still present. The
current-source Git status attempt exited 128 without usable output through
this command path; the existing provenance record still identifies that mount
as stale commit `08b3ab8…` with unrelated dirty artifacts, not the current
checkout `6312634…`. It therefore remains unsuitable as current-source
provenance without a complete authorized transfer and source identity check.

No remote files, containers, or source state were changed. State remains:
`blocked-prerequisite; runtime-qualification-open`.

## Sonic1 source-tree inventory

The tracked async `find` check found numerous historical ClamAV build and
evidence directories under `/tmp`, but only one repository metadata directory:
`/tmp/clamav-32gb-current-20260915/.git`. No alternate current-source Git
tree is available on the host. Read-only `git -C` probes of that tree exited
128 without usable output; the existing provenance receipt remains the
authoritative source identity and records stale commit `08b3ab8…` with dirty
artifacts. Historical build directories cannot substitute for a coherent
current-source candidate.
