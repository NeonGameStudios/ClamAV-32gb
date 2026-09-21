# R03 Sonic1 no-swap runner preparation — 2026-09-20

Task ID / parent milestone: `R03` / current-source qualification runner.

## Scope

Prepare the authorized Sonic1 runner for the roadmap's no-swap and capacity
admission contract without changing the candidate source or retrying the
blocked current-source transfer.

## Host identity and observed state

- Host: `sonic1`, login profile `sonic1-camera-key`.
- Kernel identity: Linux `5.15.0-190-generic`, `x86_64`.
- CPU count: 12.
- Before preparation: 62 GiB total RAM, approximately 60 GiB available,
  8 GiB swap configured with approximately 2 GiB in use, and approximately
  88 GiB free on `/`.
- Existing Docker source mounts remain unsuitable for current-source proof;
  the available containers bind stale or damaged remote source trees.

## Change and verification

The authorized runner command was:

```text
swapoff /swap.img
```

It completed with exit 0. Fresh read-only checks then reported:

```text
Mem:   62Gi total, 2.8Gi used, 58Gi free, 58Gi available
Swap:  0B total, 0B used, 0B free
Filesystem /: 295G total, 195G used, 88G available
```

This removes the host swap failure from the runner prerequisites. It does not
prove a qualification run: the current candidate still has not been staged to
Sonic1, and no source/build/evidence identity was changed or promoted.

## Remaining blocker

The existing durable MCP-SSH current-source upload was previously denied with
`file_write_limit_exceeded`, and the MCP server fix for that lifecycle path is
not yet available. The stale/corrupt container trees must not be relabeled as
the current candidate. Once the transfer path is repaired, stage the immutable
candidate, verify its source hash and Docker provenance, rebuild Release and
sanitizer artifacts, and run the materialized, ingress, PCRE, service, and
fanotify cases.

State: `development-verified`; runner no-swap preparation passed; current-source
qualification remains staging-blocked and no capability was promoted.
