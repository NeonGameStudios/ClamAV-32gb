# R13 Sonic1 procfs PID-churn hardening — 2026-09-26

Task ID / parent milestone: R13 — process-tree resource evidence

Control: `largefile_procfs_tree_rss`

Starting commit and final tested source identity: commit `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`; dirty qualification tree; v13 source-manifest SHA-256 `c423fcaf71df0643f58cb220dea9040ee215057b687ecf531fbd6ad98784ed5c`.

## Observed failure

The v12 broad Sonic1 CTest run passed 28/30 targets. `libclamav_rust` was an environment-only failure caused by the generic CTest process inheriting the default unwritable Cargo location and was independently shown to pass with the existing offline cache. The other failure was a real sampler race:

```text
awk: cannot open /proc/<pid>/status
```

`tools/largefile_procfs_tree_rss.sh` expanded `/proc/[0-9]*/status` into path arguments for one `awk` process. A short-lived process could exit after glob expansion but before `awk` opened that path, incorrectly failing a healthy resource sample.

## Change

The sampler now iterates each candidate status file, skips entries that are no longer readable, and uses `cat ... 2>/dev/null || true` before piping complete surviving records to `awk`. Record-boundary handling keys on the `Name:` field rather than per-file `FNR`, because the records now arrive through one stream. The sampler still exits 3 when none of the requested roots is selected, so expected PID churn is ignored without weakening missing-root failure behavior.

## Provenance and verification

- Deterministic v13 package: 18,385,741 bytes, SHA-256 `b8a2c4cbebab2be960bc7e9c332086c3ec67bd783db9195f46cab53e150172fa`; repeat package byte-identical.
- MCP-SSH durable transfer: `transfer_f600c77273244e32ab26cfe14eb90281`; committed atomically and independently checksum-verified on Sonic1.
- Clean extraction `/qualification/src-v13-c423fcaf` regenerated the expected 1,711-entry source manifest as non-root.
- Direct `sh tools/largefile_procfs_tree_rss_test.sh` passed from the clean v13 extraction before the full build.
- Clean Release build job `job_bcd69d125f7848029f757a98df0327ab` exited 0.
- Broad CTest job `job_c2ec9e73e9f64ba5903c0fba93d56e69` passed 30/30 in 79.98 seconds. `largefile_procfs_tree_rss` passed in 0.05 seconds, `largefile_procfs_tree_metrics` passed in 10.03 seconds, `largefile_procfs_tree_oom` passed in 0.15 seconds, and offline `libclamav_rust` passed in 13.06 seconds.
- The same v13 build subsequently passed the fully allocated exact-32-GiB library scan in 346.05 seconds under job `job_e5b85e2f5ebf406491719492d3340354`.

## Qualification boundary

This is current-source Linux x86-64 runtime evidence for the PID-churn correction and the registered resource controls. It does not by itself provide a capability-specific production workload trace, PCRE phase transition proof, sanitizer parity, production-CVD/service canary, privileged fanotify evidence, or release readiness.

State: `implemented; Sonic1 runtime-verified; release qualification pending`
