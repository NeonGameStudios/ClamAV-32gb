# R10 milter `SkipAuthenticated` file-list hardening receipt

Date: 2026-09-17 UTC

## Scope

This slice covers the file-backed `SkipAuthenticated` list constructor in
`clamav-milter/allow_list.c`, assigned to the R10 milter ingress and
`feature:ENABLE_MILTER` capability rows.

It also covers the adjacent `Whitelist`/`AllowList` reader in the same
translation unit, where a one-character final entry without a newline was
previously discarded by subtracting one byte before trimming.

## Defects fixed

- An empty or comment-only list previously reached `regex[rxused - 1]` with
  `rxused == 0`, writing before the allocation and potentially corrupting
  memory during milter startup.
- A nonempty line near the 2048-byte input buffer limit could expand to three
  regex bytes per source byte while the old code allocated only one 2048-byte
  chunk.
- The final growth allocation did not preserve the old pointer on failure.
- A one-character final `Whitelist`/`AllowList` entry without a newline was
  silently discarded.
- A malformed allow-list regex was linked into the list before compilation,
  sending failure cleanup through an uninitialized regex object.

The implementation now trims line endings with size-safe indexing, calculates
the encoded regex requirement before writing, checks `size_t` overflow, accepts
an empty/comment-only file with authenticated-user bypass disabled, and checks
the final terminator allocation.

## Focused regression

`unit_tests/check_milter_skipauth.c` is registered as
`largefile_milter_skipauth` when the application and milter are enabled on
Unix. It covers:

- an empty file;
- a comments/blank/directive-only file; and
- a 2047-byte entry whose characters expand to three regex bytes each; and
- a one-character final allow-list entry without a newline; and
- a malformed allow-list regex whose cleanup must remain safe.

The production source and test compile cleanly under strict local syntax
checks:

```text
cc -std=c99 -Wall -Wextra -Werror -fsyntax-only ... unit_tests/check_milter_skipauth.c
cc -std=c99 -Wall -Wextra -Werror -fsyntax-only ... clamav-milter/allow_list.c
```

The complete large-file source guard suite passed, including the 604-row
capability manifest, readiness tests, inventory freshness, acceptance schemas,
fanotify evidence tests, and protocol controls.

The standalone runner `tools/largefile_milter_allow_list_regression.sh` also
compiled the exact production `allow_list.c` with only the unavailable full
ClamAV regex/logging link layer stubbed, then passed the focused test both
normally and with AddressSanitizer plus UndefinedBehaviorSanitizer.

Clang static analysis of the production translation unit is warning-free after
making the allocation invariant explicit.

## Qualification boundary

No capability was promoted. The linked CTest was not executable in this
checkout: the preinstalled toolchain container has CMake and Clang but no
Cargo 1.97+, so project configuration stops before compiling; no software was
installed. Full milter-linked CTest, sanitizer, one-request resource,
current-source Sonic1, production-database/service, and certified Linux x86-64
evidence remain required.
