# R05 materialized 32-GiB-plus-one limit fixture preparation — 2026-09-29

This is preparation for the missing `clamscan:file:limit-edge` input, not a
full-size fixture or scan result. The current Sonic1 qualification filesystem
does not have enough free space; no 32-GiB-plus-one file was created.

The existing `largefile_boundary_corpus.sh` intentionally creates **sparse**
boundary controls. Sparse metadata rejection is already separately tested by
the FILDESREPORT probe, but it cannot satisfy the materialized limit case.
On Sonic1's dedicated ext4 qualification volume, a transient 1-MiB probe
showed why allocation-only creation is insufficient:

| Method | Size | Allocated | First `SEEK_HOLE` | Read head |
| --- | ---: | ---: | ---: | --- |
| `os.posix_fallocate` | 1,048,576 | 1,048,576 | 0 | eight zero bytes |
| Actual streamed write | 1,048,576 | 1,048,576 | 1,048,576 | eight `Z` bytes |

Both tiny probe files were inside a new temporary directory and were removed
by its normal cleanup. Because the acceptance input verifier requires
`st_blocks*512 >= size` **and** first hole at EOF, the large fixture must be
fully written rather than merely preallocated.

New `tools/largefile_materialized_limit_fixture.py` has a fixed CLI size of
34,359,738,369 bytes, an explicit `--acknowledge-full-write` switch, and no
CLI size override. It streams a deterministic nonzero pattern, overlays a
reviewed tail marker, syncs, checks regular-file size/allocation/hole layout
and the first/tail bytes, rehashes the complete file, and publishes without
replacing an existing destination. On write failure it removes only its own
exclusive partial. Its preflight requires at least the fixture size plus
68 GiB of post-write disk-backed admission headroom and 1 GiB safety reserve:
108,447,924,225 free bytes before writing. A separate `findmnt`/admission
check must still prove that the chosen destination is disk-backed and that
the runner has >=48 GiB effective available memory when the actual scan runs.

Focused small-size tests passed 5/5, covering a fully written and hashed
1-MiB-plus-one input, low-disk refusal before creating a partial, existing
destination protection, injected write-failure cleanup, and mandatory CLI
acknowledgment. The full `sh tools/largefile_source_guards.sh` passed after
adding this test, including the 604-capability map and release-readiness
regressions. These tests do not prove the full-size fixture or limit behavior.

## Pinned full-size content oracle added after the v13 build

The generator now also refuses to publish the full-size destination unless
the complete on-disk SHA-256 equals the independently precomputed digest
`e5ac6089ac04599810af19a2d93858c841e307037fa016f90efad197ec606720`.
The expected 34,359,738,369-byte stream consists of the repeated `00..ff`
pattern through byte `34,359,738,350`, followed by the 18-byte
`CLAMAV-LIMIT-PLUS1` tail. Two independent in-memory streaming calculations,
one in 4-MiB blocks and one in 1-MiB blocks, agreed on the digest without
creating a large local file. The focused tests now pass 7/7, including an
independently constructed small pattern accepted with its pinned digest and
a mismatching pinned digest that leaves neither destination nor partial.
The full local source-guard suite passed again, including the 604-capability
map. This edit is **after** Sonic1's frozen v13 package/build and is not part
of that v13 source identity. A new v14 tooling snapshot was subsequently
frozen and tested separately on Sonic1; no v14 scanner build was made.

The v14 deterministic package `/private/tmp/clamav-limit-v14-20260929.tar.gz`
is 17,927,446 bytes with SHA-256
`807c53289e29111fe6fe569c00f1f1e9686e5296b212bc4f2366eeb70f7d55b5`.
Its source-content manifest SHA-256 is
`edcd484f88dd8ef336694432526c1f16d90e1a9e2d1deaefa16aca6636b9abb3`.
MCP-SSH durable transfer `transfer_2dc2f52e3b234dd9b005a688195e866c`
completed with the expected checksum and atomic rename. The extracted
`/qualification/source-limit-v14-20260929` tree regenerated a byte-identical
Git-less manifest (`job_2b982957af2c4531966354acfb943035`, exit 0;
`cmp` exit 0). Focused Linux x86-64 tests passed 7/7; full Sonic1 source
guards `job_e2bb525f507b4d38a52d313265929a83` exited 0 and covered
all 604 capability-map rows.

A live v14 admission probe used the fixed-size CLI with its explicit
`--acknowledge-full-write` switch and a new
`/qualification/limit-v14-32gplus1-20260929.bin` destination. It returned
the expected exit 1 **before writing**: required free bytes
108,447,924,225; actual free bytes 3,556,114,432. A separate `test ! -e`
for the destination and a top-level partial-name search both confirmed
absence afterward. This demonstrates safe refusal on the current volume,
not a completed full-size fixture or scan.

The dedicated LV expansion remains subject to user approval. After adequate
disk and memory provisioning, freeze the final source package, run the fixed
generator on Sonic1, independently rehash/validate the 32-GiB-plus-one input,
create a pre-scan oracle bound to the same source/build/config/database, and
run the measured `clamscan:file:limit-edge` case. A sparse file or an older
candidate's case is not a substitute.

State: `v14-generator-and-admission-verified; full-size-limit-input-and-scan-pending`
