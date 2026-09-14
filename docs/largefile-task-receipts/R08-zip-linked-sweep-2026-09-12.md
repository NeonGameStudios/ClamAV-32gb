# Task receipt: ZIP linked sweep

Task ID / parent milestone: `R08` / parser-family sweep

Exact capability kind:id list: `parser:CL_TYPE_ZIP` and
`parser:CL_TYPE_ZIPSFX`; focused library coverage includes
`library:zip-map`, `library:zip-sfx-central-admission`,
`library:zip-entry-context`, `library:zip-sticky-completion`,
`library:zip-helper-map-reader-admission`, `library:zip-bzip2-finalization`,
and `library:zip-inflate-finalization` through their registered focused cases.

Starting source manifest identity:

- Source manifest SHA-256: `0efece36509e28c0d0268e553acd3b48d8a37035a5896edc14c32e41433901e6`
- Test binary: `/tmp/clamav-current-build/unit_tests/check_clamav`
- Test binary SHA-256: `a5c873802f6eb3b495f369035cceac33bb41b3c8254810355281d66cd93734a0`
- Platform: disposable AArch64 Linux Docker toolchain

The current source was compiled and linked through the production static
`check_clamav` target. Focused current-source execution passed with zero
failures and zero errors:

- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=zip_map`: **3/3 checks**
- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=zip_sfx`: **5/5 checks**
- `CK_RUN_SUITE=cl_suite CK_RUN_CASE=zip`: **19/19 checks**

The regular ZIP group includes the sticky-completion, decoder-finalization,
callback-status, central-directory, and embedded-child corpus regressions;
the SFX group includes weak-candidate rejection, bounded central admission,
malformed ZIP64 handling, and exact nested-child matching.

This is current-source development evidence, not release qualification. The
rows remain pending until certified Linux x86-64, sanitizer, production-CVD/
service, resource, full-size, Sonic1, and final release evidence is verified.

No GitHub workflow action, commit, push, or usage reset was used.
