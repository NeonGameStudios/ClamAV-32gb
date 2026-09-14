# R08 current-source MSXML empty-child MaxFiles accounting — 2026-09-13

## Scope

The streaming MSXML parser created a temporary callback spool for a
recognized `MSXML_SCAN_CB` element, but invoked the callback only when
character data had been observed. An empty recognized callback element could
therefore bypass its owner's descriptor admission, inclusive `MaxFiles`
accounting, and cache-taint propagation.

## Changes

- `libclamav/msxml_parser.c` now invokes the callback for every created
  callback spool, including zero-byte output. The existing Base64 fix in the
  same streaming finalization path continues to admit empty decoded children.
- `unit_tests/check_clamav.c` adds a callback that uses the production
  descriptor-admission helper and a regression with the enclosing XML layer
  already consuming the only `MaxFiles` slot. The empty callback child must
  return `CL_EMAXFILES`, preserve the exact limit reason, and mark the fmap
  non-cacheable.
- `tools/largefile_source_guards.sh` protects the implementation and the
  registered regression.
- The generated `docs/largefile-inventory.tsv` was refreshed after the test
  insertion.

## Verification

The retained `rust:1.97-bookworm` ARM64 Docker development container was
reused; no software was installed.

- Current-source Release `check_clamav` rebuilt successfully. The focused
  `CK_RUN_CASE=test_msxml_empty_callback_counts_toward_maxfiles` CTest passed
  `1/1` in `0.24` seconds.
- Current-source ASan/UBSan `check_clamav` rebuilt successfully. The same
  focused CTest passed `1/1` in `1.21` seconds with no sanitizer diagnostic.
- Retained Release test log:
  `/private/tmp/clamav-r08-msxml-empty-callback-maxfiles-release-20260913.log`,
  SHA-256
  `f323cfb8283ec0808eee3d702fc12c2c4137a40b6d510dfca539ad70b794a091`.
- Retained ASan/UBSan test log:
  `/private/tmp/clamav-r08-msxml-empty-callback-maxfiles-asan-20260913.log`,
  SHA-256
  `9ffa96fd09d4f934222f105dcbc58306357ea23fb5d7d1b633a85b78fe733492`.
- Full source-guard sweep passed, including the 602-capability map and
  zero-record acceptance schema. Retained log:
  `/private/tmp/clamav-r08-msxml-empty-child-source-guards-20260913.log`,
  SHA-256
  `de65d6080860c728e2ffe77d4fe22653d37ced2b806316b5d1ffac910e2ad735`.
- Snapshot freshness, regenerated inventory comparison, and `git diff --check`
  passed. The current source manifest has 1,697 entries and SHA-256
  `92a0e7af420fbdeba5a1e6b5f72b6eff52e164f0b1e7030a8d3f8058dc86fb1c`.
  The regenerated inventory SHA-256 is
  `847da0c1c3ca955990635ad1e9497e8b4b9954af7553da6eba96387767844d46`.

## Qualification boundary

This is current-source ARM64 development evidence. It does not qualify the
MSXML/XML/OOXML/HWPML parser families' exact/materialized 32-GiB cases,
certified Linux x86-64, production CVD/service behavior, resource sidecars,
privileged fanotify, Sonic1, or final release readiness. No capability was
promoted. No usage reset, commit, push, or GitHub workflow action was used.

State: `development-verified; parser-family-qualification-open`.
