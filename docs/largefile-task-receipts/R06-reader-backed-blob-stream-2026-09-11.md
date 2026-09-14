# Task receipt: R06 reader-backed OneNote blob streaming

Task ID / parent milestone: `R06` / `R00`

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE`

Scope: remove the modern OneNote scanner's whole-blob `Vec<u8>` requirement for
stream-backed FSSHTTPB object-data blobs. This is a bounded implementation
slice; it does not promote OneNote or release readiness.

Starting state: branch `largefile-roadmap-qualification`, HEAD
`8e837b88c89874b180a1a25f22d287f7d6be29db`; the existing dirty working tree,
privacy cleanup, deferred history-cleanup wishlist, and prior roadmap changes
were preserved. No commit or push was made.

## Observed gap and correction

The reader-backed modern parser already fetched source bytes incrementally, but
`ObjectDataBlob` still converted each declared blob into a `Vec<u8>`. A large
embedded file therefore remained subject to the parser's whole-payload
materialization boundary before the scanner could write it to ClamAV's
temporary spool.

The new path now:

- represents parser blobs as either bounded in-memory data or a private
  temporary-file spool;
- copies stream-backed blob data through the existing 64 KiB reader window;
- exposes spooled blobs through a reader without copying them into a second
  `Vec<u8>`;
- adds `Parser::scan_section_reader`, which walks page-level, title, outline,
  child, and table-cell attachment locations through the reader callback; and
- changes the scanner-facing modern OneNote path to consume that reader in
  bounded 64 KiB ClamAV temporary-spool writes with incremental reservation.

The compatibility `Section`/iterator APIs remain bounded and materializing by
design. Parser-owned spool files unlink on drop, including parse or traversal
errors.

## Verification

- A temporary current-source parser manifest omitting only the unavailable
  `insta` dev dependency compiled and ran the parser library unit profile:
  **70 passed, 0 failed**, including
  `stream_blob_uses_a_private_spool_without_materializing_payload`.
- The disposable current-source OneNote consumer harness passed **21/21**.
- The host tooling suite passed **147 tests with 2 expected skips**.
- Service workload checks passed **28 tests with 2 expected Linux-only skips**.
- Acceptance-map and record-schema checks passed for the current manifest;
  `git diff --check` and shell syntax checks passed.

The ordinary package check remains blocked before compilation because offline
Cargo cannot resolve the pre-existing uncached `insta` dev dependency. A full
current C/Rust consumer build remains blocked on this host before Rust
compilation by the missing `openssl/ssl.h` header. Docker and MCP-SSH were not
available, and no software, usage reset, banked reset, or GitHub workflow
action was used.

No full valid >256 MiB modern OneNote fixture, production-linked current
consumer binary, sanitizer run, certified Linux x86-64 run, production-CVD or
service qualification, Sonic1 run, or release qualification is claimed.

State: `development-verified`; the R06 capability remains `pending`.
