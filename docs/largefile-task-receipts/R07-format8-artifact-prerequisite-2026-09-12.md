# Task receipt: R07 independent bytecode format-8 prerequisite — 2026-09-12

Task ID / parent milestone: `R07` / `R00`.

Exact capability kind:id list: `matcher:bytecode-format-8-independent-artifact`.

Starting commit and working-tree/source identity: branch
`largefile-roadmap-qualification`, commit
`8e837b88c89874b180a1a25f22d287f7d6be29db`, with the intentionally dirty
working tree preserved. No host dependency installation, usage reset, commit,
push, or GitHub workflow action was used.

Roadmap contract: R07 requires an already available compatible external
compiler or independently compiled format-8 artifact to be located first. If
neither exists, the slice must be recorded as blocked with its exact external
dependency; it must not install, download, or contact anyone to obtain one.

Audit performed:

- The active disposable `rust:1.97-bookworm` ARM64 container exposes GCC
  (`/usr/bin/gcc`) but no `clang`, `llvm-as`, or `llc` binary.
- A repository file search found no independent format-8 compiler output or
  `.bc`/`.ll` fixture. The existing generated `bytecode.cud` is a legacy
  ClamAV database fixture, not an independently compiled format-8 artifact.
- Existing interpreter/JIT and bytecode API tests remain useful development
  coverage, but cannot establish the independent format-8 provenance required
  by R07.

Exact blocker/dependency for the coordinator: provide an authorized,
compatible format-8 compiler or an independently compiled format-8 fixture,
along with its source identity and hash, on an authorized Linux x86-64
qualification runner. Once available, run the interpreter/JIT, v2 globals,
cross-4-GiB read/seek/search, late-offset, mixed-v1/v2, and production
bytecode cases through the R04 evidence workflow.

State: `blocked-external-prerequisite`; no capability was promoted. Certified
x86-64, full-size, production-service, and final release qualification remain
open.

## Current-host follow-up — 2026-09-14

Apple Clang 21.0.0 is present at `/usr/bin/clang` on the arm64 macOS host,
but `clang -print-prog-name=llvm-as` and `clang -print-prog-name=llc` resolve
only to absent tool names. No `llvm-as`, `llc`, or `clambc` executable is
available, and the retained Docker image exposes none of those tools either.
A generic Apple Clang front end cannot by itself emit the ClamAV CBC header,
format-level metadata, and v2 ABI tables required for an independently
compiled format-8 fixture. The exact blocker is therefore unchanged: an
authorized compatible ClamAV bytecode compiler or compiler-produced CBC
format-8 artifact is required.
