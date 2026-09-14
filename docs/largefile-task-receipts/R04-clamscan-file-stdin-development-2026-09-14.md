# R04 clamscan file/stdin development acceptance — 2026-09-14

Task ID / parent milestone: R04 / R03 current-source application verification

Exact capability kind:id list:

- `clamscan:file`
- `clamscan:stdin`

Starting commit and working-tree/source manifest identity:

- Branch: `largefile-roadmap-qualification`
- HEAD: `8e837b88c89874b180a1a25f22d287f7d6be29db`
- Current-source manifest SHA-256: `19330bf9d99e14ef53661bf531e3cb402200abe0e395dbb44b49af86356a7667`
- The working tree was intentionally dirty; no unrelated changes were reset.

Prerequisites verified:

- Existing retained container: `clamav-current-rust-build-20260911`.
- Existing Release scanner: `/tmp/clamav-release-current-20260913/clamscan/clamscan`.
- Existing ASan/UBSan scanner: `/tmp/clamav-asan-current-20260912/clamscan/clamscan`.
- Checked-in test CVD certificate root was bound through `CVD_CERTS_DIR`/`--cvdcertsdir`.
- No software was installed and no usage-reset credit was used.

Owned files and excluded shared files: development evidence only; no production source files were changed. The repository receipt and task ledger are the only shared documentation updates.

Observed failing case and expected behavior: before this capture there was no retained R04 file/stdin `clamscan` matrix. The reviewed behavior is clean completion, exact-marker detection, and non-clean MaxFileSize admission for both file and stdin ingress.

Changes made: ran the existing `tools/largefile_development_acceptance_capture.py` against both retained binaries. Each capture created a deterministic marker fixture, clean/detection/limit databases, JSON reports, debug logs, process-status evidence, provenance, and six validated R04 records. The evidence roots were copied outside the source tree to:

- `/private/tmp/clamav-r04-clamscan-development-20260914`
- `/private/tmp/clamav-r04-clamscan-asan-development-20260914`

Commands, exits, logs and fixture/database hashes:

```text
docker exec -w /src clamav-current-rust-build-20260911 python3 -B /src/tools/largefile_development_acceptance_capture.py /tmp/clamav-release-current-20260913/clamscan/clamscan /tmp/clamav-r04-clamscan-development-20260914 --source-root /src --build-dir /tmp/clamav-release-current-20260913 --cvd-certs-dir /src/unit_tests/input/signing/verify
exit=0; development acceptance capture wrote 6 R04 records

docker exec -w /src clamav-current-rust-build-20260911 python3 -B /src/tools/largefile_development_acceptance_capture.py /tmp/clamav-asan-current-20260912/clamscan/clamscan /tmp/clamav-r04-clamscan-asan-development-20260914 --source-root /src --build-dir /tmp/clamav-asan-current-20260912 --cvd-certs-dir /src/unit_tests/input/signing/verify
exit=0; development acceptance capture wrote 6 R04 records
```

Evidence hashes:

| Evidence | Release | ASan/UBSan |
| --- | --- | --- |
| `provenance/acceptance-cases.tsv` | `8c33ec4bc6ecce487349533cc08eae087d0475071cd502bc36207ea04d4627af` | `82cba2ef9145123a61eddcdb922dc4d312d5c9326ba2905f7f9e83b2356d30d4` |
| `provenance/source-manifest.txt` | `19330bf9d99e14ef53661bf531e3cb402200abe0e395dbb44b49af86356a7667` | same |
| `provenance/CMakeCache.txt` | `f55a879d0fc1c609c1d64fa8dee8ba1b275d38d4e29de936419f8d2f77b56e57` | `eee0b5df0c3520b0fc05d502ab3657232c26b66146f7571904151403a7852b43` |
| `provenance/runtime-acceptance-oracle.tsv` | `94908c142822e9dd8822fcabd1fadf041bea8cb022f5a43547ceff218eef16a2` | same |

The six process statuses in each capture were exactly `0,1,2,0,1,2` for file clean, file detection, file limit, stdin clean, stdin detection, and stdin limit. The detection logs contain `LargeFile.R04.Runtime.Detection.UNOFFICIAL FOUND` at the expected marker offset; limit logs contain the MaxFileSize diagnostic; clean logs contain `OK`. A targeted scan of all retained logs found no `AddressSanitizer`, `UndefinedBehaviorSanitizer`, `LeakSanitizer`, or `runtime error:` diagnostic.

Development tests passed: the capture producer's report, log, oracle, source/build identity, and acceptance-record validators all passed for both binaries. Each run wrote seven TSV lines including the header, representing six records.

Full-size/certified evidence produced, or explicitly not run: no. These are small development fixtures on ARM64 Linux in the retained Docker container. They do not prove the 32-GiB boundary, certified Linux x86-64 admission, production CVD behavior, resource ceilings, service parity, or release qualification.

Remaining failures / next slice: R04 still needs materialized exact-edge and certified runner evidence, plus the remaining ingress/parser/matcher capability records. The next independent local slice can continue with an unqualified parser-family or resource case; the certified oversized probe remains externally blocked by the available ARM64 environment.

State: development-verified
