# R14 Sonic1 v3 production-CVD prerequisite retry — 2026-09-28

This is a bounded, private post-cool-down database acquisition attempt, not
an R14 canary result. The previous attempt is recorded in
`R14-sonic1-production-cvd-prerequisite-2026-09-27.md`; its stated cool-down
ended at 2026-09-28 03:18:03 UTC. This retry started at 2026-09-28 23:12:56
UTC, more than 19 hours later. No production daemon or system database was
modified.

The updater was the current v3 Release `freshclam` binary at
`/qualification/build-yc-stream-v3-20260928-release/freshclam/freshclam`,
SHA-256 `4098e9d10539632e3a3df2221e4a1d7b47da3891666b14d5da8175e896ece395`.
Its deterministic source package and extracted manifest are identified in
`R12-sonic1-v3-onenote32g-and-build-2026-09-28.md`. It used the existing
private database directory `/qualification/production-db-v15-20260927`,
retaining `freshclam.dat` and thus the previous cool-down state. The old
private config names the v15 source's `certs` directory; its `clamav.crt`
SHA-256 is `60200e4b4b1b1b7257bb4550487aeb142034341f3300a8526e77a3134a940e9d`,
identical to the v3 source certificate. The execution used the same local
container image as the v3 build on `sonic1` / `sonic1-camera-key`, a
short-lived bridge-network container with UID 1000, all capabilities
dropped, no-new-privileges, and private
`/qualification/r14-v3-cvd-20260928-tmp` scratch.

Managed job `job_5c8f0755d2e3433c80f08cdcb48b68ac` exited 17.
FreshClam itself stated that the prior cool-down had expired, found daily
remote version 28137, then received HTTP 403 for `daily.cvd` from the CDN.
Its diagnostic cf-ray ID was `a4266f949d79fb94-MIA`. It set a new cool-down
**until after 2026-09-29 23:12:57 UTC** and reported `Forbidden; Blocked by
CDN`. The exact cause of the CDN denial remains unproven; no blind retry or
version/cool-down bypass is justified.

Afterward, the private directory still held only the 90-byte
`freshclam.dat`, not a `.cvd` or `.cld`; the case scratch directory was empty
and the ephemeral updater container was absent from `docker ps -a`. No
production CVD canary ran. An authorized current signed database source or
resolution of the CDN denial is still required. No software was installed,
no usage reset was used, and no GitHub workflow, commit or push was changed.
