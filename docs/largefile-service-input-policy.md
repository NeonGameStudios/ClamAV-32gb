# Service qualification input policy

The service qualification gate must distinguish an actual large-file workload
from a small or sparse input with a convincing label. The input checker now
applies the following policy before starting a service and when verifying the
resulting evidence.

| Role | Required input |
| --- | --- |
| `edge` | Exactly 34,359,738,368 bytes (32 GiB), with filesystem-reported allocation covering the complete file and no reported holes. |
| `materialized` | Nonempty, with filesystem-reported allocation covering the complete file and no reported holes. This role alone does not imply an exact-32-GiB case. |
| `production`, `expansion` | Regular files matching the oracle's size and SHA-256. These roles alone do not establish production-CVD identity or complete parser-family coverage. |

There is no production switch or environment setting to reduce the edge size
or bypass allocation checks. A 32-GiB-minus-one or 32-GiB-plus-one file cannot
stand in for the accepted exact-edge input. A separate sparse FILDESREPORT oversized-rejection workload was added in the
[September 5 follow-ups](largefile-qualification-followups.md). Fully allocated
oversized release fixtures and other ingress modes remain required.

## Filesystem admission

For `edge` and `materialized`, the checker requires `st_blocks * 512 >= st_size`
and `SEEK_HOLE(0) == st_size`. Missing allocation information, unsupported hole
queries, insufficient allocation, and reported holes reject qualification.
Admission runs before hashing, so an enormous sparse control fails without
reading its logical contents.

This is a conservative policy based on the qualification filesystem's
reported allocation. It does not prove that every byte was independently
written or occupies unique physical storage. Reflinks can share allocated
extents; filesystem implementations can conservatively report EOF for hole
queries. Compressed or preallocated fixtures may fail these checks. Use
fully written fixtures on the intended Linux qualification filesystem and
retain the filesystem details with the host evidence. A stronger exclusive
extent/no-compression certification would need additional filesystem-specific
evidence; this change does not claim it.

Hashing and allocation inspection use one open descriptor. The checker
rejects nonregular inputs and changes to file identity, size, write timestamps,
or allocation observed while hashing. It also checks that the pathname still
refers to the inspected file. This detects ordinary concurrent replacement or
mutation; it is not a filesystem snapshot mechanism.

## Evidence and invocation

The service producer calls the same strict helper at admission and after its
workloads:

```sh
python3 tools/largefile_service_workload_check.py --check-inputs \
  ORACLE.tsv PRODUCTION_FILE MATERIALIZED_FILE EXPANSION_FILE EDGE_FILE
```

It records `provenance/service-inputs-before.json` and
`provenance/service-inputs-after.json`. Version 1 records each role's absolute
input path, size, SHA-256, allocated bytes, and first reported hole (null for
roles without hole requirements). The two records must match. Both enter the
service evidence checksum manifest.

The post-run workload verifier requires these records, independently checks
the actual inputs, and compares them with the recorded allocation/content
evidence. Older bundles without these records no longer satisfy the current
service input policy. They remain historical evidence for their own source
revisions.

## Lightweight controls and release limits

Run `python3 tools/largefile_service_workload_check_test.py` for targeted input
policy controls and `sh tools/largefile_service_evidence_check_test.sh` for the
combined service verifier controls. The latter invokes the former and uses an
isolated, scaled copy for its synthetic positive cases. It also requires the
unmodified production CLI to reject its tiny edge fixture. Scaling occurs
only in a disposable test copy; synthetic results never qualify a release.

These controls do not establish production-CVD qualification, actual
materialized 32-GiB scan success, parser-specific evidence, PCRE memory
behavior, or fanotify/on-access parity. `SERVICE_POSTRUN_EVIDENCE` remains
bounded and the branch remains release-blocked until those gates close.
