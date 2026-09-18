# R13 clamonacc evidence-option documentation — 2026-09-17

## Scope

Align the installed `clamonacc(8)` documentation with the evidence sinks
already exposed by the current source:

- `--report-json=FILE`
- `--fanotify-evidence=FILE`

## Result

`docs/man/clamonacc.8.in` now documents both options. The descriptions state
that reports are appended as JSONL, that scan reports are retained only after a
terminating daemon report or emitted as one fail-closed fallback, and that
fanotify evidence records the actual permission response without changing
on-access policy.

This is documentation alignment only. It does not claim a Linux x86-64,
full-size, privileged fanotify, or release qualification result.
