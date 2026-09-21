# R13 Sonic1 materialized exact-size PCRE resource diagnostic — 2026-09-20

## Scope and result

This receipt records a current-source-bound diagnostic run against a fully
materialized exact 32-GiB regular file. It is stronger than the earlier sparse
PCRE run for input allocation, but it is not a release qualification or a
claim that `matcher:pcre` is qualified. The positive PCRE alert terminates the
scan before a legitimate deep-parse phase, and Sonic1's host-level no-swap and
disk-capacity prerequisites are not satisfied.

The trackable MCP-SSH job was `job_8623f9b41efe415eae56a47db85f9717` on host
`sonic1` using profile `sonic1-camera-key`. The container was
`b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`, image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`,
with the writable `/src` bind from `/tmp/clamav-32gb-7f3458c4`.

## Input and build identity

- Fixture: `/src/clamav-32g-materialized-20260920/fixture-32g-tail.bin`.
- Logical size: `34359738368` bytes.
- Allocated blocks: `67108944` 512-byte blocks (`34359779328` bytes).
- Independent allocation check: `SEEK_DATA(0)=0`, `SEEK_HOLE(0)=34359738368`.
- Tail marker: `5441494c4d41524b` (`TAILMARK`).
- Release `clamscan` SHA-256: `7f5ffa200805aab9aeb73769d598219adec7f55a6e66af0618f28d1b97fb0550`.
- Source manifest SHA-256: `00b1f89e99d47102bd654c5aecde6ad9ad2413ffb370eeb6c4abed0ef3eb8058`.
- Build identity SHA-256: `58f3b6897485969e6777e0a441fb94e0d0d779f1000f3d55cd4a3082bb6e602d`.
- Configuration SHA-256: `b42c508d2d72cf7eb498cba3263a515e8d6a98086b9cec97d04718b2d5490609`.

The scan used `--max-filesize=32G`, `--max-scansize=64G`,
`--max-matcher-work=256G`, `--max-temporary-size=64G`,
`--max-contiguous-size=32G`, and `--pcre-max-filesize=32G`, with the custom
`PcreTail.UNOFFICIAL` database and explicit `/src/certs` directory.

## Observed result

The process log reported `PcreTail.UNOFFICIAL FOUND`, `Data read: 32.00 GiB`,
and a 190.732-second scan. The structured report recorded:

- `completion=DETECTION_TERMINATED`;
- `root_size=logical_bytes=contiguous_bytes=34359738368`;
- `matcher_bytes=34368129024`;
- `temporary_bytes=0`, `parser_operations=1`, and `last_alert=PcreTail.UNOFFICIAL`;
- phase file: `pcre-start`, `post-pcre`, `complete`.

The independent process-tree resource row recorded 1,573 samples:

| Metric | Value |
| --- | ---: |
| RSS peak | 33,641,056 KiB |
| PSS peak | 33,638,056 KiB |
| VAS peak | 33,691,832 KiB |
| swap peak | 0 KiB |
| temporary peak | 0 bytes |
| OOM events / kills | 0 / 0 |
| PCRE RSS peak | 33,641,056 KiB |
| post-PCRE RSS peak | 86,624 KiB |

Evidence hashes:

- resource sidecar: `cf4298b82ffd6898846c918d7d88dd0b5a883dd2c33f4e24369cc77f173ce428`;
- phase file: `a1917770ee2192298a3ac5d2f07c2f5f20d52f8189e8c5af65a2a20d60763c35`;
- process log: `699ca4b77776114a90e9034eb44988b95112023c1adcfac6c32a4092e3b05ee7`;
- structured report: `8d9e2e212479d928244ada47996c9dc426ee276002319d6c09c4971424c275d4`;
- sample trace: `7e18c2fa957fe7b33275f8ca59d3b3e1fb7a27e5127c2f615f17cad7baa2fce1`.

## Acceptance boundary

Sonic1 reported `MemTotal=65234456 KiB`, `MemAvailable=63518720 KiB`, and
24 GiB free on the root filesystem after cleanup. `/swap.img` is an 8-GiB
active swap device with `2119958528` bytes already used. The process-tree row
itself observed zero swap and zero OOM events, but that does not satisfy the
roadmap's host-level no-swap prerequisite or its 68-GiB disk-backed staging
requirement.

The positive detection stops before deep parsing, so this receipt cannot prove
parser/deep-inspection behavior. It does prove that the release executable can
read and PCRE-match a fully allocated exact 32-GiB file under the stated scan
budgets without process-level swap, temporary-file growth, or OOM events.

No software was installed or downloaded, no GitHub workflow was changed or
triggered, and no capability was promoted. The final readiness gate remains
blocked.
