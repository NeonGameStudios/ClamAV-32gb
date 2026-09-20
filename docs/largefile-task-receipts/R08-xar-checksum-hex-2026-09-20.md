# R08 XAR checksum declaration validation — 2026-09-20

## Scope

Closed one concrete XAR parser gap from `xar-checksum-declaration-admission`:
the declaration parser checked supported algorithm and digest length, but did
not reject a same-length digest containing a non-hexadecimal character.

## Change

`libclamav/xar.c` now validates the complete SHA-1/MD5 declaration through the
shared hexadecimal decoder before retaining it. A malformed non-hexadecimal
declaration returns `CL_EFORMAT`, marks the recognized XAR layer incomplete,
and leaves the input fmap non-cacheable instead of reaching the later checksum
mismatch path.

The existing `test_xar_checksum_declaration_is_fail_visible` regression now
uses an exact-length SHA-1 value ending in `g`, alongside the unsupported-style
control. The source guard requires the shared hexadecimal validation call and
the malformed-declaration path.

## Verification

- `sh tools/largefile_source_guards.sh` — passed; 604 capability rows.
- `python3 -B -m unittest discover -s tools -p '*_test.py'` — 229 passed, 2 expected skips.
- `git diff --check` — passed.

This is bounded current-source implementation/test evidence only. Current
source-linked production execution, complete XAR corpus, sanitizer, certified
Linux x86-64, production-CVD/service, Sonic1, resource, and final release
qualification remain required.
