# R05 Sonic1 live FILDESREPORT 32-GiB-plus-one probe — 2026-09-25

Task ID / parent milestone: `R05` / `R03`, `R04`

Exact capability kind:id list: `clamd:FILDESREPORT`,
`feature:SERVICE_POSTRUN_EVIDENCE`. This is a sparse descriptor-size metadata
control only; it does not qualify materialized oversized input or any other
ingress.

Starting commit and working-tree/source identity: branch
`largefile-roadmap-qualification`, commit
`5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`; dirty working-tree status captured
in the candidate as SHA-256
`dd862b5f237223f45b2673b3352f2770fc6c8ee961c288f476614928feeda6c1`.
Source manifest SHA-256
`cbe3bf9835244a7772fedac0be958c670792aaca5d98248f86addff4113f864d`;
deterministic source-package SHA-256
`2c2384602db9e4ada4e3cee7c1ab63871d0e400caef2909eb834a4cbe077d308`.
Current clean-case build identity SHA-256
`a4d267c325113973c6435f6cedde7e3a80c93f3dfa539752d1c8747b7debd938`.

Prerequisites verified: Sonic1 x86-64, container
`37c15f1f08b9325834e0dc487c09e6e0631c62275a9deb3e93654266cc042bb5`, image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`;
Release `clamd` SHA-256
`e90573fff5558cbd8daec38e0e48666abf5068a094beeaedad311b17718b9be7`.
Before the run, `MemAvailable=63,720,812 KiB` (required 50,331,648 KiB),
qualification filesystem free space was 78,085,996,544 bytes (required
73,014,444,032 bytes), and swap was zero. No software was installed.

Observed case and expected behavior: the current-source daemon must reject a
regular descriptor of exactly 34,359,738,369 bytes at the `MaxFileSize=32G`
boundary before parser, matcher, logical-byte, or temporary-staging work. With
`AlertExceedsMax=no`, return `LIMIT_INCOMPLETE` / `CL_EMAXSIZE`; with alerts on,
return the exact `Heuristics.Limits.Exceeded.MaxFileSize` policy detection.

Changes made: no application source changes. Ran the candidate's
`tools/largefile_service_oversize.py` against two fresh current-source daemon
instances using the separately recorded `clamd.conf` files. The helper SHA-256
was `5d7ccc743bf37fa38b6bf8183f5a2741539bbb0c1b1440b624ce570c58e66ac1`.
Each helper invocation was
`python3 -B <helper> <socket> <evidence.json> <tmp-dir> 60 <off|on>`; the
combined evidence was produced and revalidated by the helper's `--combine`
mode. Both generated 32-GiB-plus-one fixtures were sparse (size
34,359,738,369; allocated bytes 0), had stable before/after metadata, and were
removed after the probe.

Commands, exits, report and evidence hashes: both probe invocations and bundle
validation exited 0. The alerts-off report was `LIMIT_INCOMPLETE`, status 24,
verdict 0; alerts-on was `DETECTION_TERMINATED`, status 0, verdict 3, with the
exact policy alert. Both reports recorded root size 34,359,738,369,
`logical_bytes=0`, `matcher_bytes=0`, `temporary_bytes=0`,
`parser_operations=0`, and `skipped_operations=1`. Both modes answered PONG
before and after. Evidence directory:
`/qualification/r13-report-consistency-fix-v3-20260925/runs/fildes-oversize-v3-20260925`.

- Bundle SHA-256: `eb412bf9462cd1f24419c4b0f9a89c98a5f8e487c9a5bf3691cd7736a03a0321`
- Run summary SHA-256: `9a6f6d3a117a58b2060d4615bcb2f5e1b5b334fcf37985552f59ecb4362ee18a`
- Input provenance SHA-256: `e499e384f2085cf88ffb38f1298b087dab69e04a7cf398008ba3c1947815736d`
- Alerts-off evidence SHA-256: `d6abb6dc591866fc3722c47a15097074602a853652665a6997d6c8bb8c538589`
- Alerts-on evidence SHA-256: `44e2b95a35bdcd679294e2e6a7790d970c6048f971e62ff627f9cfb347def766`
- Database `clean.ndb` SHA-256: `4d40c958043ec8294b88b3c9b9fa9cb5a0f067b3a867bbb4517f0303c85936116`

Development tests passed: the independent post-run check reloaded and
validated both evidence records and the combined bundle, and recomputed the
bundle, input-provenance, config, daemon-log, and per-mode evidence hashes.
Both daemons exited 0; PID/socket paths and temporary directories were absent;
no `clamd`, `clamscan`, or `clamonacc` remained. Cgroup OOM/OOM-kill counters
were zero and swap remained zero.

Full-size/certified evidence produced, or explicitly not run: live current-source
Linux x86-64 sparse metadata-boundary evidence only. This does not claim a
fully materialized 32-GiB-plus-one scan, production-CVD canary, or capability
qualification.

Remaining failures / next slice: R05 still needs materialized family fixtures
and independent parser/oracle coverage. R03 sanitizer qualification remains
unavailable because this container has no `clang`/`clang++` and only the stable
Rust 1.97.1 toolchain; no installation was attempted. R04, R10-R15 and the
full capability matrix remain open; authoritative readiness is still blocked.

State: `development-verified; sparse-oversize-probe-live; not release-qualified`
