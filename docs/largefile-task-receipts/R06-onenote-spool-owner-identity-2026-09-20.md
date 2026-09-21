# R06 OneNote spool owner-identity revalidation — 2026-09-20

Task ID / parent milestone: `R06` / `R03`.

Exact capability kind:id list: `parser:CL_TYPE_ONENOTE`.

Starting source state: branch `largefile-roadmap-qualification`, prior local
commit `ca79df2d` (`Record local verifier revalidation`). The change was made
against the current vendored OneNote parser source. No host dependency,
software installation, usage reset, remote transfer, or GitHub workflow action
was used.

## Failure addressed

The current parser's spool replacement regression failed on the Linux Rust
container when a spool pathname was unlinked and replaced by a regular file.
The existing `(device, inode)` identity could be reused by the temporary
filesystem, allowing the replacement to pass the check and making cleanup
unsafe. The other spool tests then appeared as lock-poison cascades.

`ReaderSpool` now retains a cloned owner file handle after materialization. The
writer is still closed, while reader validation and cleanup derive the owner
identity from the live original inode. Synthetic test fixtures without an
owner handle retain the previous stored-identity fallback.

## Verification

The current parser source was copied into a disposable `rust:1.97-bookworm`
container. The repository's pinned root `Cargo.lock` and the existing local
Cargo registry/git caches were supplied read-only; the test ran offline:

```text
cargo test --offline
```

Results:

- 85/85 OneNote parser unit tests passed;
- 6/6 parser integration tests passed;
- 1 doctest was ignored as expected;
- the replacement-regular-file regression passed;
- FIFO, symlink, partial-spool cleanup, budget accounting, zero-length,
  private-permission, and nested-reader tests passed;
- `git diff --check` passed.

The container is Linux ARM64 development infrastructure, not the certified
Linux x86-64 Sonic1 qualification runner. The container did not relink the
full ClamAV application, run a materialized 32-GiB parser corpus, exercise
production CVD/service or fanotify paths, or produce sanitizer evidence.

## Qualification boundary

This closes the identified current-source OneNote spool identity regression at
the parser-library development level. It does not promote
`parser:CL_TYPE_ONENOTE` and does not change the blocked release-readiness
state. Full ClamAV-linked current-source evidence, certified x86-64 resource
evidence, materialized deep-parse coverage, and the remaining ingress,
sanitizer, service, and production-CVD gates remain open.

State: `implemented`; parser-library revalidation passed; certified R06
completion remains pending.
