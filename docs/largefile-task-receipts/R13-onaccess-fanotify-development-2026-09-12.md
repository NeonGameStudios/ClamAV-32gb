# Task receipt: R13 on-access fanotify development run — 2026-09-12

Task ID / parent milestone: `R13` / `R00`.

Scope: repair current-source on-access state, descriptor, reporting, malformed
event, and pathname-boundary issues and run a real Linux fanotify monitoring
exercise in a disposable privileged ARM64 development container. This receipt
does not claim permission-event or release qualification.

## Changes

- `clamonacc/fanotif/fanotif.c` now supplies `AT_FDCWD` as the pathname
  resolution descriptor to both fanotify mark calls. The fanotify event FD is
  used for event I/O and permission responses, not as the pathname `dirfd`.
- `clamonacc/client/protocol.c` now records a successful path-based
  `CONTSCANREPORT`, `MULTISCANREPORT`, or `ALLMATCHSCANREPORT` command as sent
  before entering the shared response guard. Previously `len` remained zero,
  so every continuous/path-based on-access request was relabeled `CL_EOPEN`
  without reaching the daemon response parser.
- `clamonacc/scan/thread.c` now labels ordinary `FAN_OPEN` results as
  on-access events, reports `CL_VIRUS` as malware detection rather than an
  incomplete scan, and reserves incomplete wording for actual non-clean
  failures.
- `clamonacc/fanotif/fanotif.c` now requests the full pathname buffer from
  `readlink()` and rejects an actually truncated `/proc/self/fd` result before
  any scan or report submission, releasing the event through the existing
  fail-closed path.
- `tools/largefile_source_guards.sh` now protects all five invariants.

## Build and runtime identity

The existing `rust:1.97-bookworm` ARM64 development build container rebuilt
the `clamonacc` target successfully with:

```text
cmake --build /tmp/clamav-release-current-20260912 --target clamonacc -j2
```

The resulting `clamonacc` SHA-256 is
`f0f36627823bd15ae5ddbcf3d4e4a1a03a0d5e62a42d7e1ca3dd951b144de7d7`.
The unchanged development runtime identities were:

- `clamd`: `e663583968dfe7b91da705b0fc913759d8810ec512195991b6f11a5e8cce68db`;
- `clamdscan`: `7ec20b8b5d1a0ceec6f005a50090e5ecdb2e79725018638086f2f88cc6735a3e`;
- post-fix source manifest: `8d6c0e90f49e77430e61c4f3051287138573618b01b372fe32cbec86ba01ff81`.

## Real development observations

The binaries ran in disposable privileged container
`clamav-priv-r13-20260912` with a private `/tmp/r13/watch` directory, a
current-source clamd, and the development detection database.

- A direct kernel probe initialized fanotify successfully.
- An ordinary `FAN_OPEN` mark succeeded, including with `AT_FDCWD`.
- In default continuous mode, an unprivileged open generated a real fanotify
  event; clamonacc sent `CONTSCANREPORT`, clamd logged the request and the
  `LargeFile.R04.Service.Detection.UNOFFICIAL` match, and clamonacc logged the
  file as `FOUND`.
- In fd-passing mode, a real event generated `FILDESREPORT`; clamd received
  the passed file descriptor and returned the same detection.
- In stream mode, a real event generated `INSTREAMREPORT`; clamd returned the
  same detection.
- In multiscan mode, a real event generated `MULTISCANREPORT`; clamd returned
  the same detection.
- In all-match mode, a real event generated `ALLMATCHSCANREPORT`; clamd
  returned the same detection.
- An unprivileged open of a 64 MiB + 1 byte file reached the on-access size
  preflight and was logged as incomplete with status `24` (`CL_EMAXSIZE`) in
  monitoring mode.

Retained traces, configuration, and the post-fix source manifest are in the
scoped temporary bundle `/private/tmp/clamav-r13-dev-20260912/`:

- `clamonacc-cont.log`;
- `clamonacc-r13c.log` (final event-label/status run);
- `clamonacc-fdpass.log`;
- `clamonacc-stream.log` (SHA-256
  `cf3b78a2e681678972bf81cd664e7bb631707add6f62f0ac53fede5dd4675c2a`);
- `clamonacc-multiscan.log` (SHA-256
  `ebbcca17ec05e332225d5ff0d6000a8a9bd4875b7124fcf6b2bbbd50631f53ea`);
- `clamonacc-allmatch.log` (SHA-256
  `94b0e70bd55c246f924d5fcfd32d4ab47032c7a90ae02b3f3ecddff5cc8fd422`);
- `clamonacc-path.log` (SHA-256
  `43f248e2bf9788bd3965209d0f32e46162cd8ec6451f1136c60d65f5940f6994`);
- `clamonacc-path-continue.log` (SHA-256
  `375f1ec796de31371b43a889090c882bdb91b450ba254fa51ad9a6d2b50678e8`);
- `clamonacc-path-recovery-final.log` (SHA-256
  `8ca59c77d04e4736d6e4fd8e446244dd5c5a3b959136dabe633b3efb8967a160`);
- `clamd.log`;
- `clamd-r13b.log` (SHA-256
  `b9736c6c8850b0a076be14c1f29f0d6a43fb5e19101764f9567691a46065b2ee`);
- `clamd-path.log` (SHA-256
  `e5892130c9f38dd5c427592f7e1684432cb90a6249666f7fedfd32d098d94599`);
- `clamd-path-continue.log` (SHA-256
  `a28e42d4a326249aef8fe38ab14ffa8460550fcca031445ee1ba9a8e087974fb`);
- `clamd-path-recovery-final.log` (SHA-256
  `33adfbfdf0ca38724366d6dbd6c0d070550387d30f96d0cb54c87f60d684fd39`);
- `clamd.conf`;
- `fanotify-probe.log`;
- `long-path-evidence.txt` (SHA-256
  `22492fb9b4b289a66a4d58ea840aa18b5af72cbbb6b503e80606f25399fdabab`;
  full fixture pathname length `1238`);
- `source-manifest-final.txt`;
- `source-manifest-null-guard.txt`;
- `source-manifest-path-guard.txt` (SHA-256
  `66c49bc37c2cd23b1b85ca646cae1d71025ee76e9dc62562a52a5becd3a9fe36`);
- `source-manifest-path-recovery.txt` (SHA-256
  `8d19f02597a5541ce99002b8be7da2a0e60ea97f71fb3d2b8382eba5900cccd4`).
- `source-manifest-path-recovery-final.txt` (SHA-256
  `744f52b7f43bebe75000b8eb9606953c5d8136d88e9acc6b29610adcb9ccaa49`).
- `source-manifest-path-recovery-current.txt` (SHA-256
  `06879db50293b857d8f8ea76e4e3d012419f63b918c11422bfa07cb734212e09`).
- `source-manifest-working-tree-final.txt` (SHA-256
  `6831c6997594987bc608aff005204832ff4399f48d79b8ad6dd665a7dcbac7d8`).

## Follow-on malformed-event audit

The worker's malformed fanotify context path now also tolerates a queued event
whose `ONAS_SCTH_B_FANOTIFY` bit is set but whose copied metadata object is
missing. The scan helper rejects that context as `CL_EARG`; the worker now
chooses its diagnostic label without dereferencing the missing object and then
releases the event allocation safely. This closes a local crash-on-error path;
it does not add permission-event evidence.

The current-source `clamonacc` target rebuilt successfully in the existing
disposable ARM64 build container. Its new SHA-256 is
`39a36a8c582fee4e54c563ca09f08bd7493e7e06459283cfe37a80796d2d12de`, and the
new source manifest is
`5519e24e83b0ac9354f5d0d7814545cd3bb63d18cd325a2c9173ebd2dba7129c`.
`source-manifest-null-guard.txt` is retained in the temporary evidence
bundle. The stream, multiscan, all-match, default, and fd-passing runtime
traces above predate this null-only guard and are not relabeled as runtime
evidence for the new binary.

State: `implemented; development-compiled; permission-evidence-blocked-by-test-kernel`

## Follow-on pathname-boundary audit

The current-source binary was run in monitoring mode with a short `/tmp`
mount-watch configuration and a materialized nested fixture whose full
pathname was 1,238 bytes. The event loop logged
`pathname for event fd 15 exceeds the supported length; refusing the event`,
did not submit that truncated pathname to clamd, and shut down the scan queue
cleanly. The retained `long-path-evidence.txt`, `clamonacc-path.log`, and
`clamd-path.log` bind the fixture and observed behavior.

The rebuilt `clamonacc` SHA-256 for this pathname-boundary source is
`6478856599524219535c8dfcc3bc464ffcbf8e1746e1d7fd42bc200ed3bb2bd7`, with
source manifest
`66c49bc37c2cd23b1b85ca646cae1d71025ee76e9dc62562a52a5becd3a9fe36`.
This is development monitoring evidence only; it does not add permission
allow/deny evidence or change release qualification.

## Follow-on event-loop recovery audit

The pathname-boundary handling now treats an oversized resolved path as a
single rejected event. It closes or denies that event through
`onas_release_failed_event()`, continues through the remaining fanotify batch,
and only stops the event loop if that recovery response or close fails. A
fresh current-source monitoring run proved the behavior: the 1,238-byte path
was refused, clamonacc remained live, and a subsequent unprivileged open of
`/tmp/r13/watch/detection.bin` reached `CONTSCANREPORT` and returned the exact
`LargeFile.R04.Service.Detection.UNOFFICIAL` match. The final staged binary
SHA-256 is
`f724742900bd5cef8103e5f17d65f647c61373e129028c9178cc9597df9bfb21`, with
source manifest
`8d19f02597a5541ce99002b8be7da2a0e60ea97f71fb3d2b8382eba5900cccd4`.

State: `development-verified; permission-evidence-blocked-by-test-kernel`

## Final-source pathname recovery revalidation

After the recovery handling was rebuilt from the current source, the staged
`clamonacc` binary was run in the same isolated ARM64 monitoring container.
The 1,238-byte materialized fixture produced the supported-length refusal, and
the process remained live while a later unprivileged open of
`/tmp/r13/watch/detection.bin` was submitted as `CONTSCANREPORT` and returned
the exact `LargeFile.R04.Service.Detection.UNOFFICIAL` match. The final log
hashes are retained above. The binary SHA-256 is
`f724742900bd5cef8103e5f17d65f647c61373e129028c9178cc9597df9bfb21`, and the
current-tree source manifest SHA-256, regenerated after the inventory and
tracked evidence refresh, is
`6831c6997594987bc608aff005204832ff4399f48d79b8ad6dd665a7dcbac7d8`.

The source inventory was regenerated from this same tree, the release/source
guards passed, and the tracked status snapshot was regenerated and freshness-
checked. This remains development monitoring evidence only; it does not add
permission-event evidence or change release qualification.

## Follow-on queue-teardown ownership audit

The on-access queue now clears an event's queue-node ownership before handing
it to the worker pool. Queue-owned events still linked during shutdown release
their pathname and copied metadata, and a retained fanotify descriptor is
closed or denied through the shared fail-closed release helper. This prevents
shutdown from leaking event resources or abandoning a permission event. The
worker-pool path remains unchanged: dispatched events stay owned by the worker
until `onas_scan_worker()` completes.

The current-source ARM64 Release build rebuilt `clamonacc` successfully after
this change. The full source guard suite passed, including the 601-entry
capability/acceptance controls, fanotify evidence contract, and snapshot
freshness tests. The refreshed current-tree source manifest SHA-256 is
`439eef3f46a381e4dbe6b185d3d7336b5b3cdda867ee5d8d734870e4e98811d9`.
This is a cleanup/ownership implementation audit; it does not add real
permission-event evidence or change release qualification.

## Follow-on inotify record-boundary and help-path audit

The inotify event loop now validates each record header and advertised name
length against the bytes returned by the current `read()` before advancing to
the next record. It also requires a NUL terminator within the bounded name
field before using `strlen()` or constructing a child path. Unknown watch
descriptors and nameless records advance by the validated record size, while a
short header or truncated name discards only the remainder of the malformed
batch. This removes unchecked pointer advancement and name reads from the
dynamic-directory event path.

The local `clamonacc --help` command was also moved ahead of daemon
configuration parsing and privileged fanotify startup. A host without a
`clamd.conf` can now obtain the documented usage output without an unrelated
configuration or privilege failure. `--version` retains its existing
server-version behavior and was not changed in this slice.

## Verification

- `cmake --build /tmp/clamav-release-current-20260912 --target clamonacc -j2`
  — exit `0`, warning-clean after removing the obsolete pointer variable.
- Rebuilt `clamonacc --help` smoke — exit `0`, usage output present, no stderr,
  without `/usr/local/etc/clamd.conf`.
- `sh tools/largefile_source_guards.sh` — exit `0`, including the 601-entry
  capability and acceptance controls.
- `ctest --test-dir /tmp/clamav-release-current-20260912 --output-on-failure
  -R "^(largefile_poc_fail_closed|largefile_source_guards|largefile_acceptance_case_schema)$"`
  — exit `0`, `3/3` passed in `15.12` seconds.
- Regenerated inventory: `44,666` lines, SHA-256
  `9fa51b10e63f61b7f0e8643825d63f6a40a37ad525705d03710845c99ba54c30`.
- Current-tree source-manifest SHA-256 after the final source/inventory
  refresh: `7f6c7387913854f6527445a602e10521f46c36d2e594a592921e2156fd054ac4`.
- Rebuilt `clamonacc` SHA-256:
  `0d24a6ed8b91796d7cc504c1844f06763c5e55d82da4f8ce06e66ff597e32a6e`.

## Follow-on inotify hierarchy-state audit

The dynamic-directory bookkeeping now rejects a zero or oversized kernel watch
limit before the doubled lookup-table allocation can wrap or truncate. It
also refuses empty hierarchy paths before indexing the final path byte, and
checks a stored inotify watch descriptor against the lookup-table bound before
clearing it. These are fail-visible state checks around recursive watch add and
remove paths; they do not alter normal valid-path behavior.

## Verification

- `cmake --build /tmp/clamav-release-current-20260912 --target clamonacc -j2`
  — exit `0`, warning-clean.
- `sh tools/largefile_source_guards.sh` — exit `0`, including all new
  hierarchy-state guards.
- `ctest --test-dir /tmp/clamav-release-current-20260912 --output-on-failure
  -R "^(largefile_poc_fail_closed|largefile_source_guards|largefile_acceptance_case_schema)$"`
  — exit `0`, `3/3` passed in `31.21` seconds.
- Refreshed inventory: `44,670` lines, SHA-256
  `6b965f6fd0c565940b580a44f7d5564b8bbe3a3e4de17b2a4b629ad9a68e0813`.
- Current-tree source-manifest SHA-256:
  `825ae463132f8c095a87fd77702e09f4f6b3a815e1b04dc308da033a8b194f1b`.
- Rebuilt `clamonacc` SHA-256:
  `b2d0ef4ba1725d5dcdc21dbd772b32b13d201f475ffea2b6be98726eb29393bd`.

This remains current-source ARM64 development evidence. It adds no malformed
kernel-record or real fanotify permission-event qualification, and does not
change the existing release boundary.

This is current-source ARM64 development evidence. No kernel-injected
malformed inotify record was claimed, and no fanotify permission allow/deny
evidence was added. Certified Linux x86-64, sanitizer parity, full-size,
production-database, resource, Sonic1, and final-release qualification remain
open.

## Qualification boundary

The container's kernel returned `EINVAL` (`errno 22`) when a permission-event
mask containing `FAN_OPEN_PERM` was marked. A prevention-mode clamonacc startup
therefore failed at the kernel mark step with `Invalid argument`; no
`FAN_OPEN_PERM` / `FAN_DENY` or `FAN_ALLOW` evidence was retained. This is a
kernel/filesystem capability limitation of the disposable development
environment, not permission qualification.

The run is ARM64 development evidence only. It does not promote
`on-access:permission`, does not satisfy the six-case R13 permission matrix,
and does not replace certified Linux x86-64, production-database, sanitizer,
full-size, resource, Sonic1, or final-release evidence.

State: `development-verified; permission-evidence-blocked-by-test-kernel`
