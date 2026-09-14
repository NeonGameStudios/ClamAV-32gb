# Task receipt: R04 development acceptance capture — 2026-09-12

Task ID / parent milestone: `R04` / `R00`.

Exact capability kind:id list: `feature:ENABLE_TESTS` and the six runtime
capture cases `clamscan:file:clean-edge`, `clamscan:file:detection-edge`,
`clamscan:file:limit-edge`, `clamscan:stdin:clean-edge`,
`clamscan:stdin:detection-edge`, and `clamscan:stdin:limit-edge`. These are
development evidence cases only; no capability was promoted.

Starting commit and source identity: branch
`largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. The capture-bound source manifest is
`099360edb0e59485e99ef2eff8ad0902cdd4bae7371fd96ed8fe06a28ddfffdf`.

No host dependency installation, usage reset, commit, push, or GitHub
workflow action was used. The existing disposable container
`clamav-current-rust-build-20260911` (`rust:1.97-bookworm`) supplied the
current-source ARM64 Release build at
`/tmp/clamav-release-current-20260912/clamscan/clamscan`.

Capture command:

```text
python3 -B /src/tools/largefile_development_acceptance_capture.py \
  /tmp/clamav-release-current-20260912/clamscan/clamscan \
  /tmp/clamav-dev-acceptance-20260912f \
  --source-root /src \
  --build-dir /tmp/clamav-release-current-20260912
```

The command intentionally omitted `--cvd-certs-dir`; the harness resolved the
repository test CA and rejected no-CA configurations before scanning. It
wrote six records to `provenance/acceptance-cases.tsv`:

- file clean: exit `0`, `CLEAN`, `COMPLETE`;
- file detection: exit `1`, `DETECTED`, `DETECTION_TERMINATED`, exact
  `LargeFile.R04.Runtime.Detection.UNOFFICIAL` at offset `25`;
- file limit: exit `2`, `INCOMPLETE`, `LIMIT_INCOMPLETE`, exact
  `Heuristics.Limits.Exceeded.MaxFileSize`;
- stdin clean: exit `0`, `CLEAN`, `COMPLETE`;
- stdin detection: exit `1`, `DETECTED`, `DETECTION_TERMINATED`, the same
  exact signature at offset `25`;
- stdin limit: exit `2`, `INCOMPLETE`, `LIMIT_INCOMPLETE`, the same exact
  size-limit reason.

All six records bind platform `Linux-aarch64`, the `runtime-edge` fixture,
the source manifest, build identity hash
`928e595ce14fa6f5fd6de61dfb0b95d259526b7d7531441beb6dc25803482cf6`, config
hash `22f83ada2630202a8869efab997a81125156f409f242ce8c6b7d200a2ac543c6`,
and the generated fixture/database/oracle hashes. The records report the
development resource bounds `rss<=33554432`, `pcre<=41943040`,
`post-pcre<=12582912`, and `temporary<=68719476736`; health and cleanup are
`pass` for every case.

Verification:

```text
large-file acceptance record schema passed (6 records)
```

The independent verifier was run against the retained evidence root
`/tmp/clamav-dev-acceptance-20260912f`. The clamscan binary hash is
`b085b063e507da218d1ea5ed3436a91a7572bcf11462c4ec9ff3daa17eaa99c6`.

Qualification boundary: this proves the current clamscan file/stdin
structured-report contract on ARM64 with a small deterministic fixture. It
does not prove 32-GiB behavior, certified Linux x86-64, the production CVD,
full parser coverage, resource stress, daemon/milter/on-access parity,
Sonic1, or final release qualification. Release readiness remains blocked and
no capability was promoted.
