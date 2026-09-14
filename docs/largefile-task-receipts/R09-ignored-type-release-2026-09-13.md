# Task receipt: R09 ignored-type Release integration — 2026-09-13

Task ID / parent milestone: `R09` / `R00`.

Exact capability kind:id list: `parser:CL_TYPE_IGNORED`.

Source identity: branch `largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. The current-source manifest contains 1,697 entries
and has SHA-256
`ff52df247a98e17e6b4aafcd02601f84fb00d00adcee0793f19216c54aea1a15`.
No host dependency installation, usage reset, commit, push, or GitHub
workflow action was used.

Environment: the fresh current-source ARM64 Release build in Docker at
`/tmp/clamav-release-current-20260913` was exercised through its linked
`clamscan` executable. The test creates a minimal ID3/MP3-shaped input that
the classifier recognizes as `CL_TYPE_IGNORED`, plus an exact NDB raw
signature.

Verification command:

```text
python3 -m unittest clamscan.ignored_type_test --verbose
```

Result: 1/1 test passed with zero failures and zero errors. The matching
input returned `Ignored.Raw.UNOFFICIAL FOUND` with exit 1 while retaining the
explicit `recognized ignored file type parser is unsupported` warning. The
same-shape nonmatching input returned `Can't parse data ERROR` with exit 2,
zero scanned/infected files, and the same explicit warning. This confirms the
classifier-only policy remains fail-visible without allowing raw malware
matching to be bypassed.

Qualification boundary: this is current-source ARM64 Docker Release
development evidence only. It does not prove full parser semantics,
sanitizer cleanliness, certified Linux x86-64 execution, production
CVD/service behavior, materialized-large-file behavior, Sonic1 execution,
resource qualification, or final release qualification. No capability was
promoted.

State: `development-verified`; current-source Release ignored-type policy and
raw-detection precedence passed through the application ingress.
