# Task receipt: R13 on-access configuration cleanup — 2026-09-13

Task ID / parent milestone: `R13` / `R00`.

Exact capability kind:id list: `on-access:permission`,
`feature:ENABLE_CLAMONACC`.

Starting commit and working-tree/source identity: branch
`largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. Current-source manifest SHA-256 after this slice:
`5a2baef1ece4b0d64579fb8380b03f62b751e79dd584342c318c9fcd9aeec593`
(1,697 entries).

Prerequisites verified: the existing disposable
`clamav-current-rust-build-20260911` container supplied the current ARM64
sanitizer build, CMake-generated application targets, Check, OpenSSL, cURL,
and the existing C/Rust toolchains. No package installation, usage reset,
commit, push, or GitHub workflow action was used.

Observed failing case and expected behavior: the rebuilt
`largefile_onaccess_config_admission` test rejected `OnAccessMaxThreads=0`
with the correct exit status and diagnostic, but LeakSanitizer reported a
91-byte `onas_init_context` allocation left live on that early return. Every
error path after context creation must release the owning context and its
parsed options while preserving the fail-closed exit code.

Changes made:

- `clamonacc/clamonacc.c` now routes command-line parse, logger, malformed
  daemon-config, invalid `OnAccessMaxThreads`, and daemonize failures through
  `onas_cleanup()` or the existing `done` cleanup path.
- The invalid worker-count path no longer manually frees only the option
  structures and then leaks the owning context.

Verification:

- Rebuilt the current `clamonacc` target at single-job concurrency with C
  ASan/UBSan instrumentation.
- The focused `largefile_onaccess_config_admission` CTest passed `1/1` in
  `1.98` seconds with LeakSanitizer enabled.
- The four rebuilt pool/configuration tests
  (`largefile_onaccess_threadpool`, `largefile_onaccess_config_admission`,
  `largefile_clamd_threadpool`, and `largefile_milter_connpool`) passed `4/4`
  in `5.15` seconds under the sanitizer build.
- The surrounding rebuilt application/release-control subset passed `26/27`;
  the only failure before this fix was the now-resolved on-access leak.

Full-size/certified evidence: not produced. This is ARM64 development
sanitizer evidence, not privileged fanotify kernel-event proof, a materialized
32-GiB case, certified Linux x86-64 evidence, production-CVD/service evidence,
or final release qualification.

Remaining failures / next slice: run the complete current-source matrix in
bounded groups, then address remaining implementation or resource evidence
gaps. R03 certification, R04 capability records, exact 32-GiB/materialized
cases, real fanotify privilege, production canary, and R15 release gates
remain open.

State: `development-verified`.
