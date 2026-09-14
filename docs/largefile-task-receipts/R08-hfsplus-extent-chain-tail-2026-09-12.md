# R08 HFS+ ExtentOverflow chain-tail hardening receipt — 2026-09-12

## Scope

Ensure a matching HFS+ ExtentOverflow record cannot make the resolver return
before the remainder of the declared leaf chain has been validated.

## Implementation

- `hfsplus_find_overflow_block()` now retains a matching physical block while
  continuing through every declared leaf and record.
- The resolver validates later forward links, leaf counts, cycles, record
  geometry, and extent bounds before publishing the retained block.
- A production-shaped regression corrupts the matching ExtentOverflow leaf
  into a self-linked declared tail and requires a fail-visible,
  non-cacheable `CL_EFORMAT` result.

## Verification

- Focused production-linked `hfs_fork`: `2/2`, zero failures and errors.
- Linked `libclamav` CTest target: `1/1`, with the production-linked
  `check_clamav` suite reporting `2,918` checks, zero failures, and zero
  errors.
- Source guards, status-snapshot freshness, and `git diff --check` passed.
- Source manifest: 1,697 entries,
  `52802577d6c2fe851d98801dc257a6c11f85ea70f961b35c6d1844fb3486878c`.
- Rebuilt `check_clamav` SHA-256:
  `c8f0955fb195026766300ca3ba9233c209de21f6fa666025356fd08893c2069c`.

## Qualification state

Development verification only. HFS+ still requires complete corpus,
sanitizer/leak, certified Linux x86-64, production-CVD/service,
materialized-large-file/resource, Sonic1, and final parser/release evidence.

No GitHub workflow action, commit, push, or usage reset was used.
