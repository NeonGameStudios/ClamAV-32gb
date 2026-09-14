# R08 current-source MIME empty-attachment export — 2026-09-14

## Task identity

Parent milestone: R08.
Capability: `library:mime-empty-attachment-admission`.
Starting HEAD: `8e837b88c89874b180a1a25f22d287f7d6be29db`; the working tree was already dirty and no clean qualification candidate was claimed. Current source manifest: 1,697 entries, hash `2dad186cd18993d6dd5ebaa793a8dcdb63197c2c30ba1152adaa5f84498022b8`.

## Observed gap

`messageExport()` returned `NULL` before creating any output when a recognized MIME message had no body lines. That discarded a logical empty attachment before the owning fileblob/descriptor scan path, so nested MaxFiles admission and cache taint could not apply. The pre-fix current-source control failed because `messageToFileblob()` returned no fileblob for the empty message.

## Changes

- `libclamav/message.c`: create and context-bind the export before handling a bodyless message; assign its safe attachment name, retain the zero-byte fileblob, and return it for the owning scan path.
- `unit_tests/check_clamav.c`: add and register `test_mime_empty_attachment_is_exported_for_scan`, asserting the attachment name and zero-byte temporary file.
- `unit_tests/check_clamav.c`: propagate the explicit `T` timeout to the separate MHTML TCase, so its large streaming controls receive the same bounded test budget as the other API groups.
- Add capability/case-map rows and source guards.

## Verification

- Retained `rust:1.97-bookworm` ARM64 Docker validation container; no software installed.
- Current-source Release `check_clamav` rebuilt successfully. With `CVD_CERTS_DIR` bound to the checked-in test root certificate at `unit_tests/input/signing/verify`, the complete `cl_api` run passed all 529 checks with zero failures. Log SHA-256 `12e9606ed6d742650e50c6d841d4c668674dd7c101f6ec09a35864b1d402f4fb` (`/private/tmp/clamav-cl-api-testcert-release-20260914.log`).
- Current-source ASAN/UBSAN `check_clamav` rebuilt successfully under the same matching test-certificate environment. The complete `cl_api` run passed all 529 checks with zero failures and no sanitizer diagnostics. Log SHA-256 `12e9606ed6d742650e50c6d841d4c668674dd7c101f6ec09a35864b1d402f4fb` (`/private/tmp/clamav-cl-api-testcert-asan-20260914.log`).
- Current-source Release and ASAN/UBSAN focused mail runs each passed `mail` 16/16, `mail_api` 4/4, `mail_map` 2/2, `mail_partial` 1/1, and `mhtml` 5/5 with zero failures or errors. The ASAN/UBSAN run used only the normal explicit `T=1200` override after the MHTML TCase received timeout propagation. Log SHA-256 `1a640f2044b27e2da4f5d3695de9948892cc9a8f9a9cfdc75858cebf28017493` (`/private/tmp/clamav-mail-slices-asan-normal-timeout-20260914.log`); the Release log has the same output hash at `/private/tmp/clamav-mail-slices-release-20260914.log`.
- Full source guards passed after regenerating the derived inventory and snapshot; log hash `816928c6a74f96c20d6bad4c11f6859397de7ce7cc0d017d39da6a80aaf67f9d`.
- Snapshot freshness, regenerated-inventory comparison, acceptance case map (604 capabilities), record schema check (0 records), and `git diff --check` passed.
- Current readiness status: 604 total, 0 qualified, 147 bounded, 443 pending, 14 allowlisted unsupported, 590 blocking; readiness remains blocked.

## Qualification boundary

State: development-verified; parser-family-qualification-open.
No capability promoted. Certified x86-64, exact/materialized 32-GiB, production CVD/service, resource/fanotify, Sonic1, independent format-8, complete MIME corpus, and final release evidence remain open. No commit, push, GitHub workflow action, software installation, or usage reset.
