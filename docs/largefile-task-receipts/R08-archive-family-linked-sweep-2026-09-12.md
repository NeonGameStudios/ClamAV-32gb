# Task receipt: archive-family linked sweep

Task ID / parent milestone: `R08` / parser-family sweep

Exact capability kind:id list: `parser:CL_TYPE_ARJ`,
`parser:CL_TYPE_ARJSFX`, `parser:CL_TYPE_AUTOIT`, `parser:CL_TYPE_CABSFX`,
`parser:CL_TYPE_EGG`, `parser:CL_TYPE_EGGSFX`, `parser:CL_TYPE_MSCAB`,
`parser:CL_TYPE_MSCHM`, and `parser:CL_TYPE_NULSFT`; focused library coverage
includes the corresponding ARJ, EGG, MSPack, NSIS, and AutoIt admission,
sticky-completion, extraction-status, decoder-finalization, and callback
cases registered in the named groups below.

Starting source manifest identity:

- Source manifest SHA-256: `0efece36509e28c0d0268e553acd3b48d8a37035a5896edc14c32e41433901e6`
- Test binary: `/tmp/clamav-current-build/unit_tests/check_clamav`
- Test binary SHA-256: `a5c873802f6eb3b495f369035cceac33bb41b3c8254810355281d66cd93734a0`
- Platform: disposable AArch64 Linux Docker toolchain

The current source was compiled and linked through the production static
`check_clamav` target. Focused groups passed with zero failures and zero
errors:

- ARJ: `arj_map` 8/8, `arj_compressed` 2/2, `arj` 14/14, `arjsfx` 5/5
- EGG: `egg_metadata` 1/1, `egg_map` 12/12, `egg_sfx` 3/3
- MSPack/CAB: `mspack_map` 8/8, `mspack` 8/8, `cabsfx` 3/3
- AutoIt: `autoit_map` 9/9, `autoit_corpus` 1/1, `autoit_sfx` 1/1
- NSIS: `nulsft_map` 2/2, `nulsft` 8/8, `nulsft_corpus` 1/1

This is current-source development evidence, not release qualification. The
rows remain pending until certified Linux x86-64, sanitizer, production-CVD/
service, resource, full-size, Sonic1, and final release evidence is verified.

No GitHub workflow action, commit, push, or usage reset was used.
