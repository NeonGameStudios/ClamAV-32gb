# Task receipt: R10 milter structured-reply size hardening

Task ID / parent milestone: `R10` / `R00`

Exact capability kind:id list: ingress:`milter`

Starting commit and working-tree/source manifest identity: branch
`largefile-roadmap-qualification`; existing dirty working tree preserved; the
generated inventory and snapshot were refreshed after this slice.

Prerequisites verified: the structured milter report path and existing quota
unit test were inspected; no dependency installation, remote runner, Docker
execution, usage reset, commit, push, or GitHub workflow action was used.

Owned files and excluded shared files: owned the milter reply-size contract,
its quota unit test, and the source-guard/ledger metadata. Shared release
labels and qualification records were not promoted.

Observed failing case and expected behavior: structured infected reports
constructed a legacy milter reply using unchecked `strlen(alert) + constant`
arithmetic and did not inspect `snprintf()` truncation. Overflow, an
over-limit alert, or formatting failure must refuse the reply and take the
existing fail-closed action.

Changes made:

- Added `clamfi_scan_reply_size()` with checked `size_t` arithmetic and the
  existing `CLI_MAX_ALLOCATION` ceiling.
- Used the contract before allocating an infected structured-report reply and
  reject negative or truncated `snprintf()` results.
- Added zero-length, normal, overflow, over-limit, and NULL-output unit cases
  plus source guards for the checked path.

Commands, exits, logs and fixture/database hashes:

- `git diff --check` — exit 0.
- The direct quota test compile was attempted with the host `cc`, but stopped
  before translation-unit parsing because the host lacks `openssl/ssl.h`; no
  software was installed.
- Inventory, snapshot, and full source guard results are recorded after the
  source change below.

Development tests passed: source-level controls are the available evidence;
the linked quota binary could not be built on this host because of the missing
OpenSSL development headers.

Full-size/certified evidence produced, or explicitly not run: not run. No
current-source CMake build, Linux x86-64 Release/sanitizer build, production
database, materialized large-file edge, or R04 qualification record exists for
this slice.

Remaining failures / next slice: certified milter ingress evidence, full-size
materialized service cases, current-source consumer execution, and release
qualification remain open.

State: development-verified
