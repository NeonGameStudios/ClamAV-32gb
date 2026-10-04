# R08 CVD missing-end-marker trust boundary — 2026-09-26

Task ID / parent milestone: R08 — production CVD ingress

Exact capability kind:id list: `library:production-cvd-ingress`; `library:production-cvd-api-boundary`

Starting commit and final tested source identity: commit `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`; dirty qualification tree; v13 source-manifest SHA-256 `c423fcaf71df0643f58cb220dea9040ee215057b687ecf531fbd6ad98784ed5c` (1,711 entries, 176,613 bytes).

## Problem and trust boundary

The legacy signed `test-1.cvd` fixture decompresses to four complete TAR members and then ends without either zero end-of-archive block. Its two `.info` member size and SHA-256 records match the archived `test.ndb` and `test.ldb` bytes. The original compatibility condition checked the header's logical-signature count and member-completion state. An unsigned `.cud` copy could therefore enter the exception, while a first signed-mode correction exposed a second mistake: the cryptographically signed legacy fixture legitimately advertises zero logical malware signatures. That count is neither authentication nor a nonempty-archive predicate.

The implemented boundary is prior cryptographic CVD verification, signed plus official second-stage loader mode, no unsigned mode, and a nonempty `.info` inventory whose every declared member was loaded and hash-checked. Every other missing-marker archive remains malformed.

## Changes

- Factored `cli_tgzload_may_accept_missing_eoa()` and required `CL_DB_SIGNED | CL_DB_OFFICIAL` while explicitly excluding `CL_DB_UNSIGNED`.
- Made the helper use the nonempty, fully loaded `.info` list instead of the unrelated logical-signature count.
- Retained the signed legacy fixture as the positive compatibility regression and an unsigned `.cud` copy as the negative fail-closed regression.
- Updated source guards and the pending capability description to pin the narrow historical compatibility boundary.

Owned files and excluded shared files: `libclamav/cvd.c`, the focused CVD regressions in `unit_tests/check_clamav.c`, corresponding source guards, `docs/largefile-capabilities.tsv`, generated inventory, and generated status snapshot. No capability status or release evidence was promoted.

## Deterministic handoff and Sonic1 identity

- Deterministic v13 source package: 18,385,741 bytes, SHA-256 `b8a2c4cbebab2be960bc7e9c332086c3ec67bd783db9195f46cab53e150172fa`; an independent repeat was byte-identical.
- MCP-SSH durable transfer: `transfer_f600c77273244e32ab26cfe14eb90281`; atomically committed after the remote package independently reproduced the expected SHA-256.
- Clean remote extraction: `/qualification/src-v13-c423fcaf`; the non-root regenerated manifest reproduced `c423fcaf71df0643f58cb220dea9040ee215057b687ecf531fbd6ad98784ed5c`.
- Host/profile: `sonic1` / `sonic1-camera-key`.
- Container ID: `c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`.
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`.
- Clean Release build: `/qualification/build-v13-c423fcaf-release`.
- Build cache SHA-256: `cf738195157e77db90437689d6d315b3853424f600f325f5f216459eeb39428d`; both `CLAMAV_SOURCE_COMMIT` and `CLAMAV_SOURCE_MANIFEST_SHA256` record the final manifest identity.

## Sonic1 verification

- The v11 linked `libclamav` run exposed the zero-logical-signature assumption: one of 2,958 internal checks failed because the signed legacy CVD still returned `CL_EMALFDB`. This was retained as the failing case rather than waived.
- The corrected v12 build passed the complete `libclamav` target and its 2,958 internal checks.
- Final v13 clean build job `job_bcd69d125f7848029f757a98df0327ab` exited 0 after 213 seconds with Cargo forced offline through the existing `/build/cargo` cache.
- Final v13 `libclamav` job `job_6641918a4ace44b7a2e057cb65d802aa` passed in 81.04 seconds. This includes the paired signed-acceptance and unsigned-rejection CVD regressions.
- Final v13 remaining-suite job `job_c2ec9e73e9f64ba5903c0fba93d56e69` passed 30/30 CTest targets in 79.98 seconds, including source guards, Rust, `clamscan`, `clamd`, `freshclam`, `sigtool`, archive, protocol, and resource controls.
- The exact fixture was reverified immediately before scanning: size 34,359,738,368 bytes; 67,108,864 allocated 512-byte blocks, so it was fully allocated rather than sparse; final 16 bytes `EDGE-LATE-MARKER`.
- Final v13 exact-size job `job_e5b85e2f5ebf406491719492d3340354` passed `largefile_library_exact_32g` in 346.05 seconds. A live Docker sample during the scan reported 99.50% CPU and 34.93 GiB / 62.21 GiB memory.

## Qualification boundary

This closes the current-source Sonic1 C/runtime check for the narrow missing-end-marker trust boundary and confirms the same source identity survives a real exact-32-GiB library scan. It does not provide the current production-CVD/service canary, C ASan/UBSan plus required Rust sanitizer parity, bytecode JIT, systemd integration, the complete R04 capability-specific acceptance matrix, or final release-gate evidence. Those requirements remain pending.

State: `implemented; Sonic1 current-source C/runtime verified; production/sanitizer/release qualification pending`
