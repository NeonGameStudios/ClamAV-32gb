# R04 case-private evidence routing — 2026-09-29

Task ID / parent milestone: R04 acceptance-record integration.

Starting candidate: dirty canonical `largefile-roadmap-qualification` checkout;
the last frozen and tested runtime package is Sonic1 v11, source-content
SHA-256 `bccafc652981c00f8f7b8f8b4091ff3c99c1420a1304f42d0abfa105eadf97d0`.
This change is **new local source after v11** and has no v11 runtime claim.

The acceptance-case and resource verifiers now recognize an optional
`provenance/case-evidence-roots.tsv` inside one evidence bundle:

```text
kind<TAB>id<TAB>case_id<TAB>relative_root
clamscan<TAB>file<TAB>clamscan:file:clean-edge<TAB>cases/clean
clamscan<TAB>file<TAB>clamscan:file:detection-edge<TAB>cases/detection
```

The map must name every acceptance row exactly once. Paths must be relative,
remain within the bundle, resolve to existing directories, and have no
symlinked component. Each row's retained artifacts, direct/service input
identity, actual input rehash and resource sidecar are verified inside its
mapped directory. The resource verifier requires each mapped directory's
sidecar to contain exactly the cases assigned to that directory and checks
the individual sidecar hash in each row. Without a map, the original
single-root behavior is unchanged. A service fixture role is scoped to its
case directory, so independent cases may use the same role name for different
independently hashed fixtures without borrowing each other's proof.

Owned files: `tools/largefile_acceptance_cases.py`,
`tools/largefile_acceptance_resources.py`,
`tools/largefile_case_bundle.py`, `tools/largefile_case_roots_test.py`,
and the test invocation in
`tools/largefile_source_guards.sh`. No scanner code, capability status,
default, or release criterion was changed.

The bundle builder accepts one case-private record per source directory,
copies only the row's retained artifacts (each capped at 128 MiB) and its
private TSV, writes the aggregate record/map, and verifies the staged and
published bundle. It refuses an existing output directory; it does not copy
unlisted files or an external 32-GiB input. A failed publication may leave a
new, partial output directory for inspection, but it never overwrites an
existing bundle or source evidence.
It refuses case roots from different source manifests before copying.

The authoritative release gate now passes its selected source-manifest SHA-256
to the acceptance verifier. Every case row must use that same final-source
hash; a fully self-bound older case can no longer be mixed into a newer
candidate's bundle to satisfy the case count.

Verification: focused case-root/bundle tests 12/12, existing acceptance-case tests
17/17, existing resource tests 7/7; full
`sh tools/largefile_source_guards.sh` exited 0, including the 604-row case map
and release-readiness regression suite. Adversarial controls reject missing,
duplicate, parent-traversing, and symlinked map entries; swapped directories;
missing or substituted artifacts; absent or mismatched resource sidecars; and
a well-formed bundle that combines two different source manifests.

This is development-verified schema/integration work. It does not create a
global R04 case bundle or qualify `clamscan:file`. The two v11 direct-file
cases live in separate sibling evidence roots; a future immutable bundle must
place case directories under one root (without copying the 32-GiB input),
include the required limit and sanitizer cases, and pass the authoritative
release gate on the final source. Current Sonic1 admission remains below the
48-GiB memory and 68-GiB disk-backed free-space thresholds.

State: `development-verified; runtime-repackaging-and-required-case-matrix-open`
