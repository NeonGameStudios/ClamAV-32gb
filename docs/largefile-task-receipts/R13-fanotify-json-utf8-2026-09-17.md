# R13 fanotify evidence JSON pathname hardening — 2026-09-17

## Scope

Harden the native fanotify evidence serializer used by
`clamonacc --fanotify-evidence`. POSIX pathnames are arbitrary byte strings;
the serializer now preserves valid UTF-8 sequences and emits malformed bytes
as JSON `\\u00xx` escapes so an invalid filename cannot corrupt the retained
JSONL artifact.

The follow-up review found that the first implementation accidentally routed
valid four-byte UTF-8 through the malformed-byte path. The production helper
now handles the three-byte and four-byte ranges separately, preserves valid
code points through U+10FFFF, and still rejects overlong encodings, surrogate
code points, out-of-range values, and truncated sequences.

## Verification

- `sh tools/largefile_inventory.sh` output matches
  `docs/largefile-inventory.tsv`.
- `git diff --check`: passed.
- `sh tools/largefile_source_guards.sh`: exit 0; all source, manifest,
  acceptance-contract, fixture, and evidence guards passed.
- `sh tools/largefile_clamonacc_utf8_regression.sh`: passed the exact helper
  and JSON writer extracted from `clamonacc/scan/thread.c`, covering valid
  three-/four-byte output preservation and malformed, surrogate, out-of-range,
  and truncated inputs.
- `python3 -B tools/largefile_status_snapshot.py --check
  32gb-current-snapshot.md`: passed.

No current-source clamonacc compile or privileged Linux fanotify runtime test
was claimed: the local host lacks the target development headers and the
authorized Sonic1 source snapshot cannot receive the current checkout through
the MCP-SSH durable-transfer policy.

State: `development-verified; runtime-qualification-open`
