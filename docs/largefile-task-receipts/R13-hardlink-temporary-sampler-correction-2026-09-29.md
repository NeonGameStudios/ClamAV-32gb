# R13 hard-link temporary sampler correction — 2026-09-29

This is a source-level measurement correction, not a retroactive rewrite of
Sonic1's v6 scan evidence or a new full-size qualification run.

The OneNote parser's `ReaderSpool::create` in
`libclamav_rust/onenote_parser/src/reader.rs` creates a second pathname
with `std::fs::hard_link(&path, &owner_path)` as an ownership marker. Both
names refer to the same `(st_dev, st_ino)` and one logical spool. The old
`temporary_size()` in `tools/largefile_acceptance_resource_capture.py`
recursively added `st_size` for each pathname, so a live parser spool and
its owner marker were counted twice in the sampled temporary-tree peak.
The v6 exact-OneNote Release positive row's historical path-sum peak was
68,710,277,120 bytes against the scanner's reported 34,359,720,552-byte
temporary high-water mark; that near-doubling is consistent with the
hard-link source behavior. The sampled peak remained below the 64-GiB
ceiling even under this conservative path-sum. It is not an estimate of
free physical staging space or an exact unique-inode peak.

The sampler now traverses the tree fail-closed and sums the largest
observed `st_size` for each unique `(st_dev, st_ino)` pair. It still rejects
symlinks and unsupported entry types and counts an unrelated copy as a
separate inode. `test_temporary_size_deduplicates_hardlink_owner_but_not_copy`
checks both cases; the focused capture test suite passed 17/17. This
change affects evidence measurement only, not ClamAV's parser or shared
temporary quota implementation.

The previous v6 evidence rows and SHA-256 values remain unchanged and
source-bound to the old sampler. They are conservative path-summed upper
bounds, not the corrected unique-inode metric. A newly frozen source
package and fresh full-size run are required before citing an exact
corrected peak or promoting a capability. No software, usage reset,
GitHub push, or workflow action was used.

The subsequently frozen v7 source package passed live, bounded
268,487,770-byte OneNote late-child cases in both Release and C
ASan/UBSan. Their corrected sampled unique-inode peaks were
261,369,856 and 263,454,720 bytes, respectively; see
`R13-sonic1-v7-bounded-onenote-sampler-2026-09-29.md`. Those bounded
results validate the new measurement path but do not replace the
still-pending exact-32-GiB rerun.
