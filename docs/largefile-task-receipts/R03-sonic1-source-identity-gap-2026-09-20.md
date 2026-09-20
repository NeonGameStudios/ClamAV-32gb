# R03 Sonic1 source-identity gap — 2026-09-20

Task ID / parent milestone: R03, current-source runner identity

Exact capability kind:id list: runner/build prerequisite; no capability
promotion attempted.

Starting commit and working-tree/source manifest identity: committed candidate
`45c69d47` on `largefile-roadmap-qualification`; the worktree was clean. A
source-only diagnostic manifest of a `git archive` of that commit, excluding
only the documented generated metadata and retained build/evidence payloads,
contained 1,704 entries with SHA-256
`0c93a00c815f2d31eff1c7aca06fef5f265aebc423acd299c06368970c571019`.

Prerequisites verified: MCP-SSH host `sonic1`, supplied profile
`sonic1-camera-key`, and Docker container
`53f6ca8d4a29f9ca60370197fb1552196aa908fb4ec4714a28b54f92edbd15a9` were
verified. The container is running the expected image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
with `/src` mounted read-write.

Owned files and excluded shared files: diagnostic only; no source files were
changed. The interrupted prior upload was reconciled through its status and
cancel APIs before the asynchronous command check.

Observed gap and expected behavior: the existing `/src` mount must not be
treated as current-source evidence unless its complete source identity matches
the candidate. Three recently changed files matched individually, but a
source-only manifest generated asynchronously inside the container contained
1,780 entries with SHA-256
`409360e0baf2c05332e130e3fe3ca6d3357d069d57e5ac248f2eba63d9f0a185`, which
does not match the candidate manifest.

Commands, exits, logs and identity:

- `ssh_docker_provenance` — exit-equivalent success; container running.
- `ssh_docker_exec sha256sum` for `matcher.c`, resource capture, and
  `scanners.c` — exit 0; all three hashes matched the current candidate.
- The documented asynchronous `docker exec ... python3` manifest job
  `job_0608bd88411a4b60b0df7e13bfcdab6f` — exit 0; remote result was
  `409360e0...a185 1780`.
- The earlier full fallback manifest job was canceled after it began hashing
  retained large fixtures; it was not used as evidence.

Development tests passed: local readiness status remains intentionally blocked
at 604 total, 0 qualified, 147 bounded, 443 pending, 14 allowlisted
unsupported, and 590 blocking rows. Snapshot, service-evidence, full local
tool, source-guard, and diff checks passed in the surrounding verification
round.

Full-size/certified evidence produced: none. The existing remote build and
clean-13 phase evidence remain development-only because the complete candidate
source identity is not bound.

Remaining failures / next slice: transfer a complete current candidate through
the durable MCP-SSH upload path, or use another authorized runner that can
hold the candidate and its evidence. Do not relabel the existing `/src` mount
as current-source evidence. No software was installed or downloaded.

State: staging-blocked; no capability promoted.
