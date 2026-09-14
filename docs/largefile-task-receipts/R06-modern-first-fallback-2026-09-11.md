# Task receipt: R06 modern-first OneNote fallback

Task ID / parent milestone: `R06` / `R00`

Scope: correct the scanner-facing OneNote dispatch so modern parsing gets
first refusal when the input begins with the shared OneNote magic. This is a
bounded implementation slice; it does not promote OneNote to release
qualification.

Canonical checkout and branch:

- `<repository-root>`
- `largefile-roadmap-qualification`
- intentionally dirty working tree preserved; no reset, clean, commit, or push

Source manifest SHA-256 captured before this receipt was added:
`d4bb756bb1728e7f9b20761746489803485becc17b40aa89b556b865bda2defa`.
Starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`.

## Correction

`libclamav_rust/src/scanners.rs` previously ran the bounded legacy marker
search before the modern reader-backed parser. The 16-byte legacy magic is
also shared by newer OneNote section files, so a valid modern document that
contained coincidental legacy-marker bytes could be misclassified as a legacy
attachment or rejected as malformed before modern parsing was attempted.

The scanner now:

1. parses through `OneNote::scan_reader` first;
2. preserves callback, deadline, spool, and parser failures immediately;
3. runs the legacy `Read + Seek` compatibility path only after a modern
   format/parse failure and an exact shared-magic prefix; and
4. preserves the modern error when the compatibility scan finds no attachment.

A focused Rust unit covers the fallback predicate for valid shared magic,
resource-limit errors, and non-OneNote prefixes.

## Verification

- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed;
  2 expected skips**.
- `sh tools/largefile_source_guards.sh` — **passed; 597 capability entries**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **passed**.
- `git diff --check` — **passed**.
- `cargo check --manifest-path libclamav_rust/Cargo.toml --locked --offline` —
  blocked before compilation because the offline cache lacks the `insta`
  package required by the vendored OneNote parser test dependency. No package
  was installed or downloaded.

Release readiness remains intentionally blocked and unchanged at 597 total,
0 qualified, 143 bounded, 440 pending, 14 allowlisted unsupported,
0 unsupported required, and 583 blockers. No certified Linux x86-64,
sanitizer, full-size, materialized-edge, production-service, or final-canary
evidence was produced. No remote execution, remote SSH, usage reset, GitHub
workflow action, commit, or push was used.

State: implementation slice verified by source/host controls; release
qualification remains blocked.
