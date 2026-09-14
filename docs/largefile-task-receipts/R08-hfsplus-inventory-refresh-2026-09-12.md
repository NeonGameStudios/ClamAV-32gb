# Task receipt: R08 HFS+ inventory refresh — 2026-09-12

Task ID / parent milestone: `R08` / `R00`.

Scope: reconcile the generated source inventory after the current HFS+
ExtentOverflow implementation and resource-fork regression changes. No source
behavior was changed in this slice.

The first current-source CTest run completed 27 of 28 targets successfully.
`libclamav` passed its 2,918 internal checks, and every other executed target
passed except `largefile_source_guards`, which correctly rejected the stale
tracked inventory. The inventory was regenerated from the current checkout and
verified byte-for-byte against the generator output:

- `docs/largefile-inventory.tsv`: 44,877 lines;
- inventory SHA-256: `4f6c40a1ce3148c023d7968e0170c20c91d6c082bde661a358c227476537f22`;
- current source manifest: 1,697 entries;
- source-manifest SHA-256: `6fb259e48bb36879ff8464826a0922779259bceaa98fd4787af9974b19af3b6b`.

The repaired guard passed independently as CTest `1/1`; the capability
manifest validator passed all 601 entries; the snapshot freshness check and
`git diff --check` passed. The authoritative readiness gate remains blocked
(`601` total, `0` qualified, `147` bounded, `440` pending, `14` allowlisted
unsupported, `587` blockers, and `80/80` parser rows blocked).

After the inventory repair, the complete configured CTest matrix was rerun
and passed `28/28` in `332.49` seconds. The prepared Docker container was
stopped after verification.

This is development bookkeeping evidence only. It does not promote HFS+ or
any other capability, and certified Linux x86-64, sanitizer, full-size,
production-database/service, resource, Sonic1, fanotify permission, bytecode
format-8 artifact, and final release evidence remain open.

State: `development-verified; derived-inventory-reconciled`
