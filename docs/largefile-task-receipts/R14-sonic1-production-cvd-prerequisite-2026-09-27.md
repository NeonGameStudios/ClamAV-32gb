# R14 Sonic1 production-CVD prerequisite — 2026-09-27

Task ID / parent milestone: R14 — private production-database canary, prerequisite investigation only.

The candidate was the immutable v15 source-manifest SHA-256 `e5b0d36e0ac086aed6c0d9fe7037ef0c3ba1fb9fd6f2b3ac38a14891c4e4b04f`, with the clean Release build `/qualification/build-v15-e5b0d36e-release` on `sonic1` / `sonic1-camera-key`. The normal qualification container ID was `c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`, image ID `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.

## Checks and attempts

- No `/var/lib/clamav` directory existed on the Sonic1 host. A root-equivalent search of the dedicated qualification tree, to depth six, found no `.cvd` or `.cld` file larger than 10 MiB. These checks do not prove no database exists elsewhere on the host.
- Prepared private, disk-backed `/qualification/production-db-v15-20260927` and `/qualification/freshclam-v15-20260927.conf`, using the tested build's `freshclam`, the v15 source's `certs/clamav.crt`, and `TMPDIR=/qualification/tmp-v15-release-tests-20260927`. No production service or configuration was changed.
- First one-shot update job `job_a2f4526ff9c54b4698fb771856b05ee1` exited 11: the normal qualification container could not resolve `database.clamav.net`. Docker inspection showed this container was deliberately launched with network mode `none`; Sonic1 host DNS worked. This was a container-network precondition, not a database or scan result.
- A short-lived probe using the same already-local image on Docker's standard bridge network resolved the official database domain. The restricted one-shot bridge updater job `job_bf2ecd67be534ae585fae70d15c785ec` exited 17: FreshClam found remote daily version 28135, then the CDN returned HTTP 403 for `daily.cvd`. FreshClam reported a cool-down until **2026-09-28 03:18:03 UTC**. The updater container was removed (`docker ps -a` found no matching container afterward). No further download attempt was made.
- The private database directory contained only a 90-byte `freshclam.dat` state file afterward, not a production CVD. Sonic1 root remained about 278,628 KiB free and `/qualification` about 54,652,180 KiB free. No software was installed or host volume resized.

## Boundary and next action

No production-CVD canary ran, and no R14 acceptance result or capability qualification follows from this attempt. The 403 alone does not distinguish an outdated updater, CDN policy, network reputation, or another server-side cause. Do not retry before the reported cool-down; use a separately authorized, current signed database source or investigate the CDN denial after the deadline. Continue independent R04–R13 implementation and evidence work while this prerequisite remains open.

State: `private production-CVD acquisition blocked by CDN 403/cool-down; production canary pending`.
