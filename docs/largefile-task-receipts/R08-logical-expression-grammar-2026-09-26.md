# R08 logical-expression grammar and nested identity — 2026-09-26

Task ID / parent milestone: R08 — matcher logical-expression slice

Exact capability kind:id list: `matcher:logical`

Starting commit and working-tree/source manifest identity: commit `5798545bcb8bd1cc0cf6777abadb7bfdfac05f2d`; dirty qualification tree; final local source manifest SHA-256 `e67d00f1376f5cddd764ed4c98bc18073a75464178b4d0dddc0195aa02f6fdda`

Prerequisites verified: the existing bounded parser rejects trailing data and overflowing decimal values. ClamAV's documented grammar permits `A=X,Y`, `A>X,Y`, and `A<X,Y`; `Y` constrains distinct signatures only when `A` is a logical block. The grammar does not define a leading numeric-colon prefix.

Owned files and excluded shared files: `libclamav/matcher-ac.c`, `unit_tests/check_matchers.c`, and deterministic `docs/largefile-inventory.tsv`; no capability status was promoted.

Observed failing case and expected behavior: the dirty candidate accepted undocumented `0:...` input by discarding its prefix. It also parsed `1>3,3` but returned false for four matches because it incorrectly applied the block-only distinct-signature threshold to a leaf. Passing block modifiers discarded their matched-ID set, preventing correct identity propagation through nested expressions.

Changes made:

- Removed undocumented numeric-colon prefix skipping so malformed expressions remain fail-visible.
- Kept exact bounded parsing of an optional second modifier value but ignored that block-only value for a single leaf.
- Preserved the matched-ID bitset while counting distinct signatures and propagated it through a passing modified block.
- Converted the colon-prefix test to a rejection control and upgraded the chained-modifier test from parse-only coverage to real evaluation, requiring nine total matches and all six matched IDs (`0x1ce`).

Commands, exits, logs and fixture/database hashes:

- Warning-clean Apple Clang C11 harness extracted the exact current parser and passed malformed-prefix rejection, whitespace parsing, chained modifier evaluation, count `9`, and IDs `0x1ce` — exit 0.
- `sh tools/largefile_source_guards.sh` — exit 0 in both the tracked checkout and clean v9 Git-less extraction.
- `git diff --check` — exit 0.

Development tests passed: exact parser execution harness and all source-guard-integrated Python/shell controls.

Full-size/certified evidence produced, or explicitly not run: no current-source production-CVD, Linux x86-64, sanitizer, or Sonic1 matcher execution was possible while Sonic1 SSH Connect timed out.

Remaining failures / next slice: rebuild current C tests on the certified Linux runner and execute the public matcher TCase plus production CVD loading. Bind any production signature failure to the exact database member and documented grammar; do not add permissive syntax as a workaround.

State: development-verified
