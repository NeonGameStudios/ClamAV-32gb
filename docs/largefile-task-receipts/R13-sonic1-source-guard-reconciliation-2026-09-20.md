# R13 Sonic1 source-guard reconciliation — 2026-09-20

Task ID / parent milestone: R13 / R01-R04 development verification

Exact capability kind:id list: `on-access:permission` plus the shared
source/evidence guard contract; no capability was promoted.

Starting commit and working-tree/source manifest identity: local candidate
`bf569538` (`Record Sonic1 stale snapshot revalidation`), clean before this
receipt. The existing Sonic1 container remained bound to
`/tmp/clamav-32gb-current-20260915`, whose recorded source revision is
`08b3ab820e40ac8bd307290b0c78c03c94884f1b`, not the local candidate.

Prerequisites verified: Sonic1 host `sonic1`, login profile
`sonic1-camera-key`, existing container
`53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9`, image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`,
and writable `/src` bind mount.

Owned files and excluded shared files: only the existing remote staging copies
of `tools/largefile_fanotify_evidence.py` and
`tools/largefile_fanotify_evidence_test.py` were reconciled. No large source
transfer, build artifact transfer, or local source change was made.

Observed failing case and expected behavior: the prior remote source-guard
run failed four fanotify evidence regressions because the stale test and
verifier did not require the retained `actor-result` artifact. The current
contract requires the actor result, cleanup evidence, monitoring-only
separation, and complete prevention matrix to fail closed.

Changes made: wrote the two small files over SFTP and verified their remote
SHA-256 values against the local files:

```text
tools/largefile_fanotify_evidence.py      d5b10b12bbb42712484915be6c568b3e387f43c22667e7e451b875e596f8bc90
tools/largefile_fanotify_evidence_test.py e4c07a339475f397eb412649d974a732c3328a43aabb1e3b83b980a08013e30d
```

Commands, exits, logs and fixture/database hashes: after Docker provenance
verification, tracked MCP-SSH job `job_9588d7655c2344ceaa5f93adabdf871a`
ran:

```text
docker exec 53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9 \
  sh -c /src/tools/largefile_source_guards.sh
exit=0; elapsed=23 seconds; stdout=294 bytes; stderr=14,651 bytes
```

The guard output reported `large-file capability manifest passed (604
entries)`, release-readiness tests passed, acceptance schema/case-map tests
passed, snapshot tests passed, and `large-file source guards passed`.

Development tests passed: all source-guard subtests, including 21 fanotify
evidence tests and the previously failing cleanup, missing-failure-case,
monitoring-only, and valid-complete-contract controls.

Full-size/certified evidence produced, or explicitly not run: no. The result
is development evidence from a stale remote source staging tree with two
small files reconciled. It does not establish current-source provenance,
certified x86-64 Release/sanitizer evidence, fanotify kernel permission
capability, full-size resource evidence, or release qualification.

Remaining failures / next slice: the complete current-source transfer remains
blocked by the previously recorded MCP-SSH durable-write policy boundary.
Sonic1 also remains below the roadmap temporary-space requirement and lacks
the required Clang/Rust-nightly sanitizer toolchain; the Docker/kernel
fanotify permission path returns `EPERM`. Re-run the full current-source
CTest only after an authorized current-source staging path exists.

State: development-verified
