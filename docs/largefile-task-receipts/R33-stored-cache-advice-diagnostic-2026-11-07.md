# R33 same-size Stored-ZIP cache-advice diagnostic — 2026-11-07

## Summary

R33 repeated the R32 960-MiB synthetic ZIP_STORED positive with the existing
source-cache advice option enabled. It was a diagnostic comparison; the fixture
size did not increase. All ten bounded controls and the complete
lease → engine-ready → budget admission → stage/seal → scan → cleanup flow
passed on Sonic1 under the 2-GiB workload cap, zero swap, and a 1-GiB scanner
tmpfs.

The scan reported the expected `PcreZipTail32G.UNOFFICIAL` detection as
`CL_TYPE_ZIP` at archive offset 1,006,632,976. It processed a
1,006,633,088-byte archive with a 1,006,632,960-byte Stored member and
2,013,266,048 logical bytes across two files. Materialized and temporary
bytes, skipped operations, and required cleanup failures were all zero. All
245,761 pages were observed resident at the scan endpoints; continuous
residency was not proven. Scanner exit 1 was the expected detection, not an
out-of-memory termination.

## Cache-advice result and resource readings

The runner issued 240 `POSIX_FADV_DONTNEED` hints covering 1,006,632,960 bytes
of consumed source-file ranges. This hint did not target the sealed scan
backing, and actual eviction or page attribution was not verified. The maximum
sampled cgroup current was 2,051,903,488 bytes, 6,148,096 bytes above R32's
sampled maximum. This small difference does not establish a regression, but it
also provides no observed peak reduction from the hint.

The watchdog collected 157 samples: maximum host nonfree memory was
40,657,346,560 bytes, minimum available memory was 62,708,731,904 bytes, and
the largest sample gap was 252,725,150 ns. These are operational samples, not
a continuous peak bound. The 1-GiB scanner tmpfs had exactly its 1-GiB required
floor available, with no additional headroom. Both containers stopped without
OOM, the slice became inactive, Docker had no running containers, and swap
remained zero. The full case and stopped containers remain on Sonic1.

## Qualification status

Keep the size ladder at 960 MiB under the current limits. The synthetic
90-byte PCRE database was used; no production CVD/CLD database or production
PCRE/normalization measurement was available. R33 does not qualify exact
32-GiB scanning, continuous residency, strict whole-workload RSS, or the
48-GiB recommended and 40-GiB minimum system profiles. The official database
refresh helper remains gated until 2026-11-08 07:43:32 UTC; its single official
endpoint attempt requires fresh preflight, and another HTTP 403 ends updater
attempts.

## Provenance

- Sonic1 job: `job_68ccb702088a48a084d7dbbf6365879c` (exit 0)
- Atomic transfer: `transfer_93a4ec7bd4874d03940004d3154f19f7`
- Frozen bundle SHA-256: `c4e782721f6afb58f78de3b91316fd6adb4c6628cb0f7f5c52c81abcfb2cc835`
- Source manifest SHA-256: `f5d4851a7bc19aefcba0479ea2a202fcad6c4ac160191d6578c78408957b7a9b`
- Runtime receipt SHA-256: `4a8dfc79029cd8f8331ae990edee5f1afc0833cc8d5ca024a539dfa42f6c05b9`
- Sonic1 case: `/tmp/clamav-qualification-disk-lv-v1/operational-small-controls-v38-v31-stored-positive-r33/case`
