# R13 Sonic1 exact-size PCRE resource capture — 2026-09-20

## Scope

Run the current PCRE phase bridge against an exactly 32-GiB logical sparse
regular file on Sonic1 and retain independently sampled process-tree resource
evidence. This is development evidence for the resource boundary; it does
not promote `matcher:pcre` or establish a materialized release qualification.

## Provenance

- Host: `sonic1`, login profile `sonic1-camera-key`.
- Container: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`.
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Container `/src` mount: `/tmp/clamav-32gb-7f3458c4`, read/write.
- Source-bound manifest SHA-256:
  `00b1f89e99d47102bd654c5aecde6ad9ad2413ffb370eeb6c4abed0ef3eb8058`.
- Release `clamscan` SHA-256:
  `7f5ffa200805aab9aeb73769d598219adec7f55a6e66af0618f28d1b97fb0550`.
- Build identity SHA-256:
  `58f3b6897485969e6777e0a441fb94e0d0d779f1000f3d55cd4a3082bb6e602d`.
- Configuration SHA-256:
  `77f4fa5abb34df1086b5fbb7c8ffed661454d7f9e061ab46c5f6c0c51c2ee89a`.

The fixture's logical size was exactly `34,359,738,368` bytes. It was sparse,
not fully materialized, so this run does not satisfy the roadmap's separate
disk-backed materialized-input requirement.

## Runtime result

The explicit certificate directory `/src/certs` was required by this
disposable container. A small positive-control smoke first loaded the custom
`PcreTail.UNOFFICIAL` signature successfully. The exact-size scan then
returned the expected detection result:

- `completion=DETECTION_TERMINATED`, scanner exit `1`;
- `root_size=logical_bytes=contiguous_bytes=34,359,738,368`;
- `matcher_bytes=34,368,129,024`;
- `last_alert=PcreTail.UNOFFICIAL`;
- scanner report elapsed time `188,314 ms`.

The phase file was `pcre-start -> post-pcre -> complete`. A positive PCRE
detection terminates before the parser dispatch, so no `deep-parse` event is
claimed from this run.

## Independent resource result

The resource recorder retained 1,538 process-tree samples and validated the
row before publishing it:

| Metric | Measured peak/result |
| --- | ---: |
| RSS | 33,636,728 KiB |
| PSS | 33,634,545 KiB |
| VAS | 33,691,832 KiB |
| PCRE RSS | 33,636,728 KiB |
| post-PCRE RSS | 82,296 KiB |
| swap | 0 KiB |
| temporary bytes | 0 |
| OOM events / kills | 0 / 0 |
| cgroup OOM count | 1, unchanged baseline |

The post-PCRE sample was acknowledged only after an independent procfs sample
fell below the 12-GiB post-PCRE budget. Transitional high-RSS samples remained
classified as PCRE peak samples. This closes the earlier RSS/PSS sampler race
without weakening the gate.

Retained artifact hashes:

- resource row: `6f1efd3ba14dbfb1bd77e43b532b678ae5f48031c930c21a8c2a134a92cf95bb`;
- phase file: `a1917770ee2192298a3ac5d2f07c2f5f20d52f8189e8c5af65a2a20d60763c35`;
- process log: `aad9694572bb7246e24cfee59c846a9204f22b59acff483953fd3fc0c89b9108`;
- JSON report: `e923e86f1f557a57163e047c4bde31ebd948b57775669fb2428615acd107f73d`;
- sample trace: `1981d4ef1689ed5386fe8591b38f59725b6e2ecfaffaadf5a15c335e730cb89e`.

## Qualification boundary

This is strong exact-logical-size sparse PCRE resource evidence. It remains
development-only because the fixture was not materialized, the positive
detection ends before deep parsing, and the formal R13 proof requires a
separate runtime marker sequence including a legitimate `deep-parse` phase.
Production CVD/service parity, sanitizer parity, fanotify, and final release
readiness remain open. No capability was promoted.

No software was installed or downloaded, and no GitHub workflow was triggered.

State: `development-verified; materialized-and-deep-parse-qualification-open`.
