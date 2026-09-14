# Task receipt: R06 OneStore object-group size validation

Task ID / parent milestone: `R06` / `R00`

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE`

Scope: validate the object data size declared in an FSSHTTPB object-group
declaration against the corresponding parsed object or excluded-object data.
This closes a malformed-input acceptance gap in the modern OneNote parser; it
does not promote OneNote or release readiness.

Starting state: branch `largefile-roadmap-qualification`, HEAD
`8e837b88c89874b180a1a25f22d287f7d6be29db`; the existing dirty working tree,
privacy cleanup, deferred history-cleanup wishlist, and prior roadmap changes
were preserved. No commit or push was made.

## Change

`ObjectGroupDeclaration::validate_data` now compares `data_size` with the
parsed `BinaryItem` length for object data and with the declared size for an
excluded object. Blob-reference declarations retain zero data size because
they carry an object-data-blob reference rather than inline object bytes.

## Verification

- A temporary current-source parser manifest omitting only the unavailable
  `insta` dev dependency passed **72/72** parser library tests.
- New coverage rejects a mismatched inline object size and accepts a matching
  excluded-object size.
- Targeted source guards and shell syntax checks passed.

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
