# R04 Sonic1 v12 tooling on two v11 cases — 2026-09-29

This receipt verifies case-private evidence aggregation and its fail-closed
source/coverage boundaries. It does **not** qualify `clamscan:file`, and it is
not a v12 scanner runtime result. The scanned clean and late-detection cases
remain the v11 source-bound Release cases recorded in
`R04-sonic1-v11-direct-file-release-2026-09-29.md`.

## Tooling package and handoff

The dirty canonical checkout was frozen into
`/private/tmp/clamav-r04-case-bundle-v12-20260929.tar.gz`, 17,924,219 bytes,
SHA-256 `d294a2ebf380a9ed23f9e325d9d97270f31a2c58474f6515d5c46c890d7df0b6`.
Its source-content manifest SHA-256 is
`3d5c04edb021c1febecfd80f90ca192a743a9566ea4ba444082eac55b351e38b`.
MCP-SSH durable transfer `transfer_53ebae69dd264808b4da4ee5703b6a16`
reached `ready_to_commit` with the expected size/hash and committed by atomic
rename. The pinned Sonic1 container
`c838d4235a6ee1fc00af5601fc25bc3212f019ee594dc09537201f79a5629197`
(image `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`)
extracted 1,721 regular files into
`/qualification/source-r04-case-bundle-v12-20260929` after rechecking the
package hash. A Git-less manifest regenerated from that tree compared
byte-identical to the packaged manifest. The full source-guard managed job
`job_9760894c1969478f8ad7950101a3a87d` exited 0, including the
604-capability map, release-readiness tests and 14-record synthetic control.

## Published two-case bundle

The case-private v11 roots were
`/qualification/r04-direct-v11-release-clean-20260929` and
`/qualification/r04-direct-v11-release-detection-20260929`, about 620,000 bytes
each; neither contains the 32-GiB fixture. The v12 builder managed job
`job_f1f3223caedd46edb0cabbe2c9b24310` exited 0 and published
`/qualification/r04-direct-v11-two-case-bundle-v12-tool-20260929`.
The bundle has 28 regular files totaling 1,209,327 bytes; its largest file is
231,144 bytes. It retains the original source roots and external input
untouched. The aggregate acceptance rows and case-root map are respectively
SHA-256 `d321146ca57faaa55a7730e5dfca27fcabd4d534a34127cdabe512685652a2b1`
and `701102333329092b2a6d284c30f24088c0e3291f2da1b5febe6c52aa6544801d`.
The map routes clean and detection to `cases/0001` and `cases/0002`.

The builder independently validated both case rows in its staging and
published directories, including full-content rehashing of their external
materialized 32-GiB input. A separate resource verifier exited 0 for both
private sidecars. The final-source check with the **v12** manifest exited 1:
`acceptance record source does not match the final candidate at line 2`.
The coverage check with the correct historical **v11** source hash rehashed
both inputs and exited 1 specifically because
`clamscan:file:limit-edge` is missing. Its first managed observation job
`job_de905eb6c73c4abf9f4506d5d6de119c` ended 1 without captured output;
the bounded direct recheck (MCP request
`req_e360228c42104af9a2edea195878eb7b`, 86.569 s) retained the exact
missing-case diagnostic. Container OOM/OOM-kill counters remained zero.

The v11 evidence cannot be promoted under v12, and even under v11 the
three-case `clamscan:file` matrix is incomplete. Fully materialized
32-GiB-plus-one-byte limit evidence, sanitizer parity, other ingress modes,
and the final-source release gate remain open. No host volume layout, fixture,
database, GitHub workflow, or usage-reset state was changed.

State: `v12-bundle-tooling-live-verified; v11-two-case-evidence-still-incomplete`
