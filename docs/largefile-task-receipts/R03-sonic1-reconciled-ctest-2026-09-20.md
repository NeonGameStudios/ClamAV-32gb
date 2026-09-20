# R03 Sonic1 reconciled registered CTest — 2026-09-20

Task ID / parent milestone: R03 / current-source development integration
recheck

Exact capability kind:id list: shared registered CTest controls; no capability
was promoted.

Starting commit and working-tree/source manifest identity: local candidate
`b4370763` (`Record Sonic1 reconciled source guards`). The remote build was
not rebuilt and remained bound to the existing staging source revision
`08b3ab820e40ac8bd307290b0c78c03c94884f1b`, not the local candidate.

Prerequisites verified: Sonic1 host `sonic1`, login profile
`sonic1-camera-key`, container
`53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`, image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`,
and `/src/build-roadmap-20260920`.

Observed failing case and expected behavior: the immediately preceding full
CTest run had failed only `largefile_source_guards` because two small fanotify
evidence files in the stale source staging tree predated the retained
`actor-result` contract. After those files were reconciled and their hashes
verified, the same registered suite was rerun without a rebuild.

Commands, exits, logs and fixture/database hashes: tracked MCP-SSH job
`job_717c2a461d0942f8a0675dfe24a664ae` ran:

```text
docker exec 53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9 \
  ctest --test-dir /src/build-roadmap-20260920 --output-on-failure --timeout 1200
exit=0; total test time=449.13 seconds; 28 tests passed, 0 failed
```

Development tests passed: all 28 registered tests, including `libclamav`,
`libclamav_rust`, `clamscan`, `clamd`, `freshclam`, `sigtool`, milter,
threadpool/admission controls, source guards, runtime/service evidence
verifiers, acceptance schema/producers, development acceptance capture,
late-member, RSS/metric/OOM controls, and the clamd report protocol.

Full-size/certified evidence produced, or explicitly not run: no. This is
development integration evidence from an existing stale remote build after a
small verifier/test reconciliation. It does not establish current-source
provenance, certified x86-64 Release/sanitizer evidence, full-size resource
qualification, kernel fanotify permission evidence, production-CVD evidence,
or release readiness.

Remaining failures / next slice: current-source remote staging is still
blocked by the recorded MCP-SSH durable-write policy boundary. Sonic1 remains
below the roadmap temporary-space prerequisite, lacks Clang/Rust-nightly
sanitizer prerequisites, and returns `EPERM` for the privileged Docker
fanotify path. The authoritative local release status remains blocked at
zero qualified capabilities.

State: development-verified
