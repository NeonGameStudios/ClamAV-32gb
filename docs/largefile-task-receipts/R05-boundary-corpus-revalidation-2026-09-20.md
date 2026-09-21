# R05 boundary corpus revalidation — 2026-09-20

Task ID / parent milestone: `R05` / `R04`

## Scope

Re-run the independent boundary-corpus generator and checker from the current
candidate. This validates the exact marker offsets and size metadata needed by
future runner work; it is deliberately not a materialized 32-GiB scan claim.

## Command and result

```text
sh tools/largefile_boundary_corpus.sh \
  /private/tmp/clamav-boundary-corpus.0k7lpb
exit=0
boundary_corpus=pass rows=11
```

The generated manifest SHA-256 was:

```text
2e0897e26f19380b3fddc7bd4af704d770904c94d08bbb43e622f83cc598b90a
```

Independent filesystem checks reported both `32g-head.bin` and
`32g-edge.bin` as exactly `34359738368` bytes. Each occupied only 32
filesystem blocks, confirming that the controls are sparse rather than
materialized. The head marker is at offset `4096`; the edge marker is at
offset `34359738304`.

## Interpretation

The boundary generator and oracle are development-verified for the current
source. They provide the reviewed sparse metadata controls and exact marker
coordinates for R05/R11, but they do not prove full traversal, disk-backed
allocation, parser/deep-inspection, sanitizer, service, or release evidence.
The temporary corpus was removed after the checks.

State: `development-verified`
