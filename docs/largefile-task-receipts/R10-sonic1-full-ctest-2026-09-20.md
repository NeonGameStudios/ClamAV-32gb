# Task receipt: R10 Sonic1 complete current-container CTest

Task ID / parent milestone: `R10` / `R03`

Scope: run the complete registered CTest inventory in the current Sonic1
container after the milter development-admission correction. This is fresh
current-container integration evidence, not a release qualification run.

Environment and identity:

- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container: `53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`.
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Source bind: `/tmp/clamav-32gb-current-20260915` mounted at `/src`.
- Build directory: `/src/build-roadmap-20260920`.

Command and result:

```text
ctest --test-dir /src/build-roadmap-20260920 --output-on-failure --timeout 1200
exit=8

27/28 tests passed.
Passed: all bounded controls, aggregate libclamav, acceptance/resource
controls, retained 32-GiB development capture, process-tree controls,
milter quota/protocol, Rust, clamscan, clamd, freshclam, and sigtool.
Failed: largefile_source_guards
Reason: large-file source guard failed: committed inventory is stale
Total test time: 468.26 sec
```

The application and its current build controls therefore passed 27/28. The
only failure is the mounted source snapshot's provenance artifact, not a
scanner or front-end assertion. The mounted hashes were:

- `docs/largefile-inventory.tsv`:
  `9cd27db0ef828d35a17c1f208c03e09696b940a63d845cb6aee781fb40464960`
- `tools/largefile_inventory.sh`:
  `02ab0d834052f59beafcb229c6fe84b5a37f9f6f47601cb1a8c045f8304843e7`

The current local candidate hashes are:

- `docs/largefile-inventory.tsv`:
  `a19d7e064a20926de7ee196e71d55b5b38127ab7510e6405a8f6c0e1d3c16e34`
- `tools/largefile_inventory.sh`:
  `f705cb1d8d70dba7f3c1af181cb0e5c90445215eb8df68f82e79ef4d7d339013`

Retained output:

- `/tmp/clamav-r10-sonic1-full-ctest-20260920.log`
- SHA-256: `d85c71c4ed53db412497a9635c7e9eb75bce159098860cb12438536af28c2fbc`

Next action: refresh the remote candidate's inventory artifacts through the
authorized durable source-transfer path, then rerun only the source guard and
the complete CTest suite against that same source identity. Do not promote
qualification from this run. Full-size certified resource, sanitizer,
production-CVD, fanotify, and final readiness evidence remain open.

State: `development-verified; source-snapshot-provenance-blocked`
