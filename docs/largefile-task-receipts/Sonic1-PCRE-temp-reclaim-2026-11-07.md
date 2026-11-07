# Sonic1 PCRE temporary-copy cleanup audit — 2026-11-07

## Purpose and scope

The October 8 exact-size PCRE receipt documents an incomplete, safety-stopped continuation. Its findings are already recorded in the ClamAV-32gb GitHub branch at qualification-evidence/2026-10-08-fmap-abi-fix-r2/current-source-62f4dd75/pcre-exact-root-20261008/receipt.md (commit 78ca5013e2529f18623372bce68e141c8f066bf8). This audit identifies only two generated temporary files that are byte-identical to a member of the retained source ZIP. It does not reclassify the incomplete scan as a pass.

No files have been removed as of this pre-deletion record. The targets below will be re-statted immediately before deletion. Only those two exact regular files are in scope; no parent directory, source, build, archive, report, log, fixture, database, container, backup, or other evidence is in scope.

## Retained source and byte identity

Source ZIP on Sonic1:

- Path: /tmp/clamav-qualification-disk-lv-v1/r12-v4-zip-exact-20261003-450fa681-disk-input.zip
- Size: 34,359,738,368 bytes
- Current full-file SHA-256: 450fa6814ec1c650461db9ae0fad6288aaa6d220642a00c2421d381eca99d85a
- Current verification: tracked read-only job job_92a9c816dec341ed9f017c0d9bf8b971, exit 0.

The retained ZIP member prefix.bin is method 0 (ZIP_STORED), size 34,359,705,207 bytes, CRC32 41db104f, SHA-256 7d7beeb1bac960b08988bfccc644f1a20ea110bc247528bd6b89ce75b36a7b96. The earlier tracked member comparison job job_04733103849a4b0d82cce02858333c43 confirmed the first temporary file was byte-identical to this member. The current candidate checksum job job_64e1a77bde3947efb28e863357fbdf52 exited 0 and independently returned the same SHA-256 for both candidate files.

## Exact verified cleanup candidates

Each target is a regular file with one hard link and size 34,359,705,207 bytes. Current stat metadata and hashes were checked on Sonic1.

1. /tmp/clamav-qualification-disk-lv-v1/clamav-current-62f4dd75-20261008/evidence/current-source-62f4dd75-pcre-exact-root-20261008/temporary/continuation/clamav-5a2418bba50d2360a2e137e951867007.tmp
   - SHA-256: 7d7beeb1bac960b08988bfccc644f1a20ea110bc247528bd6b89ce75b36a7b96
   - mtime: 2026-10-08 14:07:34 UTC; inode 11670796; link count 1.

2. /tmp/clamav-qualification-disk-lv-v1/clamav-current-62f4dd75-20261008/evidence/r5-frozen-20261009/continuation-qualification-20261009/temporary/continuation/clamav-559aaabc787883f4772c35c93af1ad2f.tmp
   - SHA-256: 7d7beeb1bac960b08988bfccc644f1a20ea110bc247528bd6b89ce75b36a7b96
   - mtime: 2026-10-09 01:55:52 UTC; inode 13266447; link count 1.

Expected space reclaimed if only these targets are removed: 68,719,410,414 bytes (64 GiB minus 66,322 bytes).

## Explicitly preserved

- /tmp/clamav-qualification-disk-lv-v1/clamav-current-62f4dd75-20261008/evidence/current-source-62f4dd75-pcre-exact-root-20261008/temporary/continuation/clamav-55bb1795d1f97331f1d2a9f7ae6e0dda.tmp — same size as the member, but SHA-256 714ccce1eac2f90b7aa7a4c1b51066ff115817baef6a7a706653059ff158b1ae, so it is not a duplicate.
- /tmp/clamav-qualification-disk-lv-v1/clamav-current-62f4dd75-20261008/evidence/r5-frozen-20261009/continuation-qualification-20261009/temporary/continuation/clamav-a8b831843671860acab51b23a77168d5.tmp — 24,107,155,456 bytes; equivalence has not been established.
- The full source ZIP, source tree, Release build, R13 receipt, raw logs, reports, databases, manifests, prior cases, current test fixtures, and all stopped containers/backups.

## Sonic1 pre-cleanup state

Read-only preflight at 2026-11-07:

- Available RAM: 64,850,505,728 bytes; swap: zero.
- Docker running-container list: empty.
- Free bytes: root 2,302,271,488; qualification 2,422,419,456; PCRE scratch 283,004,928.
- No build or scanner workload was running. The checksum jobs were read-only.

## Cleanup action and verification

After this record is confirmed present on GitHub, re-stat both exact candidate paths and require the recorded sizes, one hard link each, and matching current SHA-256 values. Remove only those two paths. Then verify both paths are absent and re-read df for the root, qualification, and PCRE-scratch filesystems. Preserve the mismatched and unverified files above regardless of remaining space. Record the observed post-cleanup values in this audit; do not claim the expected reclaimed amount until df confirms it.
