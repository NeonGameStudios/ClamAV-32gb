# R10 operational-failure parity receipt — 2026-09-07

State: development-verified on the current ARM64 disposable build; not a
certified release record.

## Identity

- Canonical source: `<repository-root>`
- Pre-receipt source-manifest SHA-256:
  `f4ac50b8210a717b549b669663e0b67c25ea39331821d2b58f2b56092a9f0774`
- `clamd` SHA-256:
  `695f651a2fa6cf6aaedff0c7776e92c41de658ebfc7453663ffca40bc150410f`
- `clamdscan` SHA-256:
  `52d9e26eb0d1de76b610dc9971695996c99680acbcfb54784ccd16a4405355f3`
- Daemon log SHA-256:
  `d0738d5b1d9410e074634149b949747cb77bf9e11ae6948a027a6a2a28721fd7`

## Case

Against the current one-worker daemon, the same missing regular-file target
`/out/does-not-exist.bin` was sent through the three multiscan client modes:

| Mode | Process exit | Report completion | Status | Verdict | Work counters |
| --- | ---: | --- | ---: | ---: | --- |
| `--multiscan` | 2 | `RESOURCE_FAILURE` | 11 (`Can't get file status`) | 0 | all zero |
| `--stream --multiscan` | 2 | `RESOURCE_FAILURE` | 11 (`Can't get file status`) | 0 | all zero |
| `--fdpass --multiscan` | 2 | `RESOURCE_FAILURE` | 11 (`Can't get file status`) | 0 | all zero |

Each report contains exactly one JSON object, names the missing target, has no
alert or detection verdict, and records zero logical, matcher, contiguous,
temporary, parser, detector, and file-scan work. The corresponding client logs
contain `ERROR: Can't access file /out/does-not-exist.bin` and no `OK` or
`FOUND` line.

Report SHA-256 for `missing-path.jsonl`, `missing-stream.jsonl`, and
`missing-fdpass.jsonl` is the same:
`bd1346a862aac99591b7f57acc60f207206868d05f87e82247919f9a800a3dce`.
Each corresponding log SHA-256 is:
`5213646de5052320e45171b38a42f5b904147377baff41094165aa189fd69974`.

## Interpretation

This confirms that a visible operational failure remains a failure across the
path, staged-stream, and descriptor-passing multiscan forms; it cannot be
mistaken for a clean scan. It does not qualify the ingress rows: certified
Linux x86-64 execution, full-size fixtures, sanitizer evidence, and the wider
R04 case matrix remain required.
