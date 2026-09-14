# R08 HFS+ resource-fork ExtentOverflow coverage receipt — 2026-09-12

## Scope

Extend the HFS+ ExtentOverflow development fixture so both data and resource
forks exercise overflow resolution, while retaining the malformed-chain
hardening regression.

## Implementation

- The production resolver already receives the owning catalog file ID and fork
  type; the fixture now binds a resource-fork record separately from the data
  fork record.
- The resource fork has eight inline blocks plus a ninth overflow-only block,
  proving that the fork-type key prevents the data-fork record from being
  reused for resource data.
- The same test corrupts the matching leaf's forward link and requires the
  complete-chain validation to remain fail-visible.

## Verification

- Focused production-linked `hfs_fork`: `2/2`, zero failures and errors.
- Linked `libclamav` CTest target: `1/1`; production-linked `check_clamav`
  reported `2,918` checks, zero failures, and zero errors.
- Capability manifest, snapshot freshness, and `git diff --check` passed.
- Source manifest: 1,697 entries,
  `e22940b895d3f25943495ce72737e9a41a592891e28861861918ead460d32b0`.

## Qualification state

Development verification only. Complete HFS+ catalog/attribute/resource
corpus, sanitizer/leak, certified Linux x86-64, production-CVD/service,
materialized-large-file/resource, Sonic1, and final parser/release evidence
remain required.

No GitHub workflow action, commit, push, or usage reset was used.
