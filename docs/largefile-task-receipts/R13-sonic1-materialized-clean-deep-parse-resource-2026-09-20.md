# R13 Sonic1 materialized clean deep-parse resource diagnostic — 2026-09-20

## Scope and result

This receipt records the clean-control counterpart to the materialized exact-size
PCRE positive diagnostic. Sonic1 scanned a fully allocated exact 32-GiB regular
file, completed successfully, and reached the real deep-parse phase. It is
resource and phase evidence for one PCRE control; it is not a release
qualification, parser-family qualification, service/on-access qualification, or
final-readiness claim.

The trackable MCP-SSH job was `job_7bbe72ac7f5c4bb894d9fc98a6ed0d54` on host
`sonic1` using profile `sonic1-camera-key`. The container was
`b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`, image
`sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`,
with the writable `/src` bind from `/tmp/clamav-32gb-7f3458c4`.

## Input, build, and configuration identity

- Fixture: `/src/clamav-32g-materialized-clean-20260920/fixture-32g-clean.bin`.
- Logical size: `34359738368` bytes.
- Allocated blocks: `67108872` 512-byte blocks (`34359742464` bytes).
- Independent allocation check: `SEEK_DATA(0)=0`, `SEEK_HOLE(0)=34359738368`.
- Tail marker: `434c45414e544147` (`CLEANTAG`).
- Source manifest SHA-256: `00b1f89e99d47102bd654c5aecde6ad9ad2413ffb370eeb6c4abed0ef3eb8058`.
- Build identity SHA-256: `58f3b6897485969e6777e0a441fb94e0d0d779f1000f3d55cd4a3082bb6e602d`.
- Configuration SHA-256: `b42c508d2d72cf7eb498cba3263a515e8d6a98086b9cec97d04718b2d5490609`.

The scan used `--max-filesize=32G`, `--max-scansize=64G`,
`--max-matcher-work=256G`, `--max-temporary-size=64G`,
`--max-contiguous-size=32G`, and `--pcre-max-filesize=32G`, with the custom
`PcreTail.UNOFFICIAL` database and explicit `/src/certs` directory. The clean
tail does not match that database.

## Observed result

The process log reported `OK`, `Data read: 32.00 GiB`, and a 178.360-second
scan. The structured report recorded:

- `status=0`, `completion=COMPLETE`, and `No viruses detected`;
- `root_size=logical_bytes=contiguous_bytes=34359738368`;
- `matcher_bytes=34368129024`, `temporary_bytes=0`;
- `parser_operations=1`, `detector_operations=1`, and `files_scanned=1`;
- phase file: `pcre-start`, `post-pcre`, `deep-parse`, `complete`.

The independent process-tree resource row recorded 1,498 samples:

| Metric | Value |
| --- | ---: |
| RSS peak | 33,638,244 KiB |
| PSS peak | 33,635,337 KiB |
| VAS peak | 33,691,832 KiB |
| swap peak | 0 KiB |
| temporary peak | 0 bytes |
| OOM events / kills | 0 / 0 |
| PCRE RSS peak | 33,638,208 KiB |
| post-PCRE RSS peak | 83,812 KiB |

The row also recorded 379,834,368 bytes of peak process-tree reads and 8,192
bytes of writes. The cgroup OOM counter was unchanged at one historical event,
with no new OOM event or kill during this run.

Evidence hashes:

- resource sidecar: `6c70e8daff69ede616e53142258ac3aa605b0fa9a71bb461f4a3d69db16db00f`;
- phase file: `2346da2d0dab2183202bb4deebf910d7799f1099909a84cf5a37037525e5c5d1`;
- process log: `40d4da4cb64724889d0ecbc19848c63b7f094d0919e9a689685172b70ad7347a`;
- structured report: `dc4097b152b4580c849f81121feb73a2ba25790a5d26830ef19210bcaba1b53d`;
- sample trace: `ecbae01cc062df90d930a0b90265268ed783a50e93aaa56d9cfcb3def189f412`.

## Acceptance boundary

The exact file was materialized in `tmpfs:/dev/shm`, which demonstrates the
64-GiB Sonic1 RAM-backed path and avoids sparse-file holes. It does not replace
the roadmap's disk-backed staging requirement. During the run the host still
had an active swap device with previously used space; the process row observed
zero swap, but the host-wide no-swap gate remains open. After the fixture was
removed, the host returned to approximately 88 GiB free disk, but that cleanup
state is not the same as proving a 68-GiB disk-backed staging run.

No software was installed or downloaded, no GitHub workflow was changed or
triggered, and no capability was promoted. Parser-family coverage, current
source staging, sanitizer parity, production-CVD/service, fanotify/on-access,
full ingress parity, and final release readiness remain open.
