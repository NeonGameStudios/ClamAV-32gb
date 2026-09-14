# Task receipt: R06 OneNote reader cleanup

Task ID / parent milestone: `R06` / `R00`

Scope: close the sink lifecycle gap on the legacy OneNote reader path. This
is a bounded implementation slice; it does not promote OneNote to release
qualification.

Canonical checkout and branch:

- `<repository-root>`
- `largefile-roadmap-qualification`
- starting commit: `b4cde643fce085fa016338339830b2b28ff9a42a`
- intentionally dirty working tree preserved; no reset, clean, commit, or push

Source manifest SHA-256 captured before this receipt was added:
`088f21ab9ce86b8f63613ca7a7da915c63c4748a8149049339ef3e56a85ff9a3`.

## Correction

`libclamav_rust/src/onenote.rs` now calls the sink's `abort()` callback
when `begin()` fails in the bounded legacy reader path before returning the
error. This preserves the sink lifecycle contract for callers that allocate
or reserve resources during `begin()`. A focused regression configures a
synthetic begin failure and verifies that abort cleanup is still invoked.

## Verification

- `cargo check --offline --manifest-path /private/tmp/onenote-parser-check/Cargo.toml --lib` — **passed** against the current parser source using a disposable manifest that omits the uncached test-only dependency.
- `cargo test --offline --manifest-path /private/tmp/onenote-parser-check/Cargo.toml --lib` — **61 passed**.
- `cargo test --offline --manifest-path /private/tmp/onenote-host-check/Cargo.toml` — **21 passed**, including the new begin-failure cleanup regression.
- `python3 -B -m unittest discover -s tools -p '*_test.py'` — **147 passed; 2 expected skips**.
- `sh tools/largefile_source_guards.sh` — **passed; 597 capability entries**.
- `python3 -B tools/largefile_status_snapshot.py --check 32gb-current-snapshot.md` — **passed**.
- `git diff --check` — **passed**.
- The host Rust toolchain has no installed `rustfmt` component; no software was installed.

Release readiness remains intentionally blocked and unchanged at 597 total,
0 qualified, 143 bounded, 440 pending, 14 allowlisted unsupported,
0 unsupported required, and 583 blockers. No certified Linux x86-64,
full-size materialized OneNote fixture, sanitizer, privileged, production
service, or final-canary evidence was produced. No remote execution,
remote SSH, usage reset, GitHub workflow action, commit, or push was used.

State: implementation slice verified by current-source parser/consumer tests
and repository controls; release qualification remains blocked.
