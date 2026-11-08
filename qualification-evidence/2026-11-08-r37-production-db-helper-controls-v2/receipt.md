# R37 production-database helper-control progress — 2026-11-08

## Result

The separately pinned v2 Linux helper-control package passed all 40 production-runner parser, snapshot, finalizer, and fixture-builder controls on Sonic1. The run took 0.059 seconds for the unit suite and used a 512-MiB worker maximum, zero swap, one CPU, 128 tasks, no network, and the unprivileged `nobody` identity.

The corrected runner verifies `cgroup.kill` on the exact non-root worker cgroup before releasing its start gate. The worker cgroup finished empty and was removed. Its watchdog recorded one memory sample during this short run, with a 251,131,321-ns maximum reported gap. That sample is not continuous host peak evidence.

Launch preflight measured 48.1646 GiB host nonfree, 60.3217 GiB available, zero swap, 2.0943 GiB free on root, and 50.9708 GiB free on qualification storage. The required 1.25-GiB projection passed the 50-GiB early-stop check.

## Scope and remaining gates

This run exercised helper controls only. It did not build ClamAV, load or update a database, write the positive fixture, or scan any input. The worker receipt records `scanner_invoked=false` and `database_loaded=false`.

The R37 source build remains deferred: its previously measured 2.129-GiB increment plus the 1.25-GiB margin projects to approximately 51.544 GiB host nonfree at this baseline. The FreshClam 1.5.4 one-attempt gate remains 2026-11-08 07:43:32 UTC; no update attempt has occurred.

The largest integrated Stored-ZIP scan remains 960 MiB with a synthetic database. Exact-32-GiB raw and Stored scanning, production-database positives, detector/PCRE coverage, continuous residency, strict RSS, and the 48/40-GiB profiles remain unqualified.

## Preserved evidence

The v2 bundle is 42,989 bytes, SHA-256 `80cf3b6c1efa08aa4a9e4920152231e2e70420cd7d7855606cd9c2a2fc46d9eb`. MCP-SSH transfer `transfer_7534d11c635c457393d9a20e8baff781` committed it atomically. The pinned helper-package manifest SHA-256 is `b4d71128b245ced76968e154b5c08d81cdadc0ee9f4a5c5af20b875ccbaf862a`.

Raw run evidence remains on Sonic1 under:

`/tmp/clamav-qualification-disk-lv-v1/residency-runtime-assurance-r1-20261108-r37-production-db-followup-v1/production-db-control-run-20261108-v2/`

Key hashes:

- `result.json`: `3c024bdb82eb57a8408ecd2ac101cf87b8f258acecec7f67362396cd808d11e1`
- `preflight.json`: `5624431d9f847cdab0e0fbe1a7b4814217fb53466ec88d7f8b88c09dcaec81c3`
- `watchdog.jsonl`: `fbe6a246a70afc0b9ffda868a124e0071e556e9fba80646b17433988daf84455`
- `worker-output/worker-result.json`: `e26a2cbf3dae16bf63b40a6e13ed20eda87a63b7259e9aa3597bbb69585c7378`
- `worker-output/unit-tests.log`: `e1d141595c56c50229e1203d23ba4100f675817f99ea5b433cd3c451576ac800`

The active qualification goal remains open.