# Task receipt: R02 resource-policy contract

Task ID / parent milestone: `R02` / `R00`

Exact capability kind:id list: `feature:large-file-resource-policy`,
`feature:large-file-runtime-evidence`, and the shared runtime/service evidence
producers and verifiers; no capability row promoted to qualified

Starting commit and working-tree/source manifest identity: current dirty
`largefile-roadmap-qualification` worktree at the active roadmap candidate;
pre-existing changes were preserved.

Prerequisites verified: PLAN.md requires RSS <=40 GiB during PCRE, RSS <12 GiB
after PCRE before deep parsing, 64 GiB temporary space, and a four-hour scan
deadline. The current producer/verifier pair only recorded one 32 GiB RSS bound.
The certified Linux x86-64 runner is not available on this macOS host.

Owned files and excluded shared files: runtime gate/evidence scripts and their
regression tests, plus service qualification/evidence scripts and synthetic
evidence setup. No parser, matcher, or daemon implementation source was changed.

Observed failing case and expected behavior: the evidence contract could not
distinguish its stricter 32 GiB whole-workload RSS subcase from PLAN.md's
40 GiB PCRE-phase ceiling and 12 GiB post-PCRE ceiling. Expected behavior is
explicitly recorded, independently checked phase budgets while retaining the
stricter 32 GiB workload gate.

Changes made: runtime and service producers now record `pcre_rss_budget_kb`,
`post_pcre_rss_budget_kb`, and `rss_budget_contract`; independent verifiers
require the exact 40 GiB/12 GiB contract and ensure the overall bound does not
exceed the PCRE ceiling. Regression evidence now fails when the post-PCRE budget
field is removed. These fields define the contract; they do not substitute for
R13's required real phase RSS sampling.

Commands and exits:

- `sh tools/largefile_runtime_evidence_check_test.sh` — exit 0.
- `sh tools/largefile_service_evidence_check_test.sh` — exit 0.
- `sh -n tools/largefile_runtime_gate.sh tools/largefile_runtime_evidence_check.sh tools/largefile_service_qualification.sh tools/largefile_service_evidence_check.sh` — exit 0.
- `git diff --check` — exit 0.
- `sh tools/largefile_source_guards.sh` — exit 0.

Development tests passed: synthetic runtime/service evidence verifiers pass and
reject missing phase-budget metadata. No full-size runtime or phase measurement
was produced.

Full-size/certified evidence produced, or explicitly not run: not run; certified
Linux x86-64 runner and CMake toolchain are unavailable.

Remaining failures / next slice: R13 must add real PCRE/post-PCRE RSS phase
sampling; R03 must establish the certified build; R04 must bind these resource
fields into capability-specific case records.

State: `development-verified`
