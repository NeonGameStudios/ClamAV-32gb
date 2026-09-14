# Task receipt: R09 real UnRAR backend Release integration — 2026-09-13

Task ID / parent milestone: `R09` / `R00`.

Exact capability kind:id list: `parser:CL_TYPE_RAR`, `parser:CL_TYPE_RARSFX`.

Source identity: branch `largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. The current-source manifest contains 1,697 entries
and has SHA-256
`ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`.
No host dependency installation, usage reset, commit, push, or GitHub
workflow action was used.

Environment: the fresh current-source ARM64 Release build in Docker at
`/tmp/clamav-release-current-20260913` was used with `ENABLE_UNRAR=ON`, the
production-linked `clamscan` executable, and the recorded UnRAR artifacts
explicitly bound through `LIBCLAMUNRARIFACE` and `LIBCLAMUNRAR`.

Fixture correction: the RAR4 test builder now computes each 16-bit header CRC
with the same standard CRC convention as UnRAR. The corrected stored archive
is 78 bytes with SHA-256
`575f8c27ef1c34295ae04591bf22f1517beaf4feaea997d61ba732a518a5252a` and
contains the ten-byte `RarPayload` member. The neutral-prefix RAR-SFX is 101
bytes with SHA-256
`1fd4560b4e0f88792dd5d1a0f08746040f18559aa1641981aa6dba1290a4235f`.
The disposable HDB is 77 bytes with SHA-256
`786ec076426a0887453272110caeeeb44af7a913dbd797cdb47314cf45948188`.

Verification command:

```text
python3 -m unittest clamscan.rar_backend_test --verbose
```

Result: 1/1 test passed with zero failures and zero errors. Both
`minimal.rar` and `minimal-sfx.exe` produced `RarChild.UNOFFICIAL FOUND` with
exit 1, and the corrected valid headers produced no archive-incomplete
diagnostic. The test therefore exercises actual RAR and RAR-SFX recognition,
UnRAR extraction, nested child scanning, and raw result reporting through the
application rather than a mocked backend.

Qualification boundary: this is current-source ARM64 Docker Release
development evidence only. It does not prove the complete RAR/RAR-SFX corpus,
sanitizer or leak cleanliness for this application case, certified Linux
x86-64 execution, production CVD/service behavior, materialized-large-file
behavior, Sonic1 execution, resource qualification, or final release
qualification. No capability was promoted.

State: `development-verified`; corrected valid RAR and RAR-SFX nested-member
application integration passed through the enabled production UnRAR backend.
