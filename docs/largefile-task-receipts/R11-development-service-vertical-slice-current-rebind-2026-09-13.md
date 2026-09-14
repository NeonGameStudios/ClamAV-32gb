# R11 current-source service vertical slice rebind — 2026-09-13

Task ID / parent milestones: `R11` / `R04`, `R10`.

The current-source ARM64 Release `clamd`/`clamdscan` development capture was
rerun after the build provenance rebind. The existing Docker container and
Release binaries were reused; no software was installed.

Evidence output: `/tmp/clamav-r04-service-release-current-20260913f`.

Source identity: branch `largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`; source-manifest SHA-256
`12aecbdf0c16bfae5aabb5480bb89554f6fcbd9e3ab77f6d2180ba43680e1f42`.

Command exited 0 and wrote 36 R04 records. Independent acceptance-record
validation also exited 0. The records cover six structured daemon report
commands and six `clamdscan` modes across clean, exact-detection, and
configured-limit outcomes: 12 `COMPLETE`, 12 `DETECTION_TERMINATED`, and 12
`LIMIT_INCOMPLETE`. Acceptance TSV SHA-256:
`c1b0be4fe2e9ff101565cdf96c6d6328bd8fdec011fdee83edf61e7cb6589397`.

The retained lifecycle artifacts bind daemon health before and after each
outcome group and normal socket/PID cleanup. This is small-fixture ARM64
development evidence, not exact/materialized 32-GiB, certified x86-64,
production CVD/Sonic1, resource-sidecar, milter, fanotify, or final release
qualification evidence. The records bind ingress capabilities only; they do
not qualify parser-family rows.

No capability was promoted. No usage reset, installation, commit, push,
workflow action, or remote mutation was performed.

State: `development-service-verified; qualification-blocked-by-runner-and-fixtures`.
