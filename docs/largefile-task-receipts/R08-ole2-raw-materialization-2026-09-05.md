# R08 OLE2 raw-materialization slice

Task ID / parent milestone: R08 / OLE2 temporary materialization and outer raw matching

Exact capability kind:id list: library:ole2-sticky-completion; parser:CL_TYPE_MSOLE2

Starting commit and working-tree/source manifest identity: `ff8905891b2b58a66c71859ab2c807cc4dee2dec`; working tree intentionally dirty with the roadmap candidate changes. The current-source inventory and source guards were regenerated and passed after this slice.

Prerequisites verified: canonical checkout `<repository-root>`, branch `largefile-roadmap-qualification`, ARM64 current-source build container, and existing roadmap acceptance/source gates.

Owned files and excluded shared files: `libclamav/ole2_extract.c`, `unit_tests/check_clamav.c`, and `unit_tests/input/other_sigs/Clamav-Unit-Test-Signature.ndb`. Shared manifests, readiness state, and qualification records were not promoted.

Observed failing case and expected behavior: the legacy file-inspection callback refused an oversized contiguous materialization, but the regression used a whole-file HDB signature and an offset-zero NDB signature, so the required outer raw pass traversed the 1-GiB-plus map without detecting the marker. The expected behavior is bounded callback refusal followed by raw substring detection, with a strong verdict and a non-cacheable incomplete map.

Changes made: OLE2 file-stream materialization now reserves the declared temporary output only after non-file properties are rejected and releases the reservation on every exit. The regression uses parser-disabled raw matching, a `0:*` NDB signature, and the NDB-qualified alert name. A temporary diagnostic TCase was removed after the normal regression remained registered.

Commands, exits, logs and fixture/database hashes:

- `cmake --build /tmp/clamav-largefile-static-build --target check_clamav -j2` in the disposable ARM64 container: exit 0.
- Isolated `CK_RUN_SUITE=cl_suite CK_RUN_CASE=legacy_focus T=30 .../check_clamav`: `1/1` passed before removing the temporary diagnostic TCase.
- Normal OLE2 current-source cases `ole2`, `ole2_map`, `ole2_xlm`, and `hwpole2_map`: `24/24`, `7/7`, `3/3`, and `5/5` passed.
- `sha256(unit_tests/input/other_sigs/Clamav-Unit-Test-Signature.ndb) = 4d40c958043ec8294b88b3c9bfa9cb5a0f067b3a867bbb4517f0303c85936116`.
- `git diff --check`: exit 0.

Development tests passed: current-source OLE2 focused tests, acceptance map/schema checks, source guards, and inventory synchronization.

Full-size/certified evidence produced, or explicitly not run: no full-size materialized 32-GiB fixture, sanitizer qualification, certified x86-64 run, production CVD/service run, or Sonic1 run; the available ARM64 evidence is development-only.

Remaining failures / next slice: release readiness remains blocked; the x86-64 runner connection timed out, and the broader capability matrix still has pending implementation/evidence rows. No capability is promoted to qualified by this receipt.

State: development-verified
