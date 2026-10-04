# R04 copy-free direct-file input binding — 2026-09-29

Task ID / parent: R04 case-specific evidence. Capability slice:
`clamscan:file` clean-edge, detection-edge and limit-edge. This is a local
verifier improvement, not a release-qualified capability or a new Sonic1
scan.

## Observed gap

The frozen v10 raw ClamScan cases retain reports, logs, database/build hashes
and process-tree resources in case-private roots, but the actual fully
materialized 32-GiB fixture is mounted separately and read-only. The generic
R04 verifier previously required the fixture SHA-256 to match an artifact
**inside** the evidence root. Copying the file into each case root would
consume another 32 GiB per copy, while merely writing its digest into a
sidecar would not prove which file ClamScan read. The v10 cases also did not
capture the new before/after identity sidecars at run time, so this change
must not be used to promote those historical cases retroactively.

## Change

`tools/largefile_acceptance_cases.py` now accepts a separate
`provenance/direct-inputs-before.json` and `direct-inputs-after.json` binding
for `clamscan:file` only. Both files must be retained in the case artifact
list, byte-identical, versioned, and contain exactly the case's fixture role
and SHA-256. Service-input evidence cannot be mixed with direct-input
evidence. The verifier requires the retained `scan-report.jsonl` to name the
actual input path, match the case's completion and counters, and carry the
appropriate exact clean, alert/offset, or MaxFileSize limit outcome. It
rejects a release-labelled clean/detection record unless the input is exactly
32 GiB, and a release-labelled limit record unless it is exactly 32 GiB + 1;
the limit report must bind the 32-GiB MaxFileSize. Small fixtures remain
development-only controls. It
requires the corresponding scan log and input hash for clean/detection;
an admission-only MaxFileSize limit must instead carry the exact diagnostic
and zero content-work counters. Finally it opens and rehashes the **actual**
external fixture, checking regular-file type, size, allocation, SEEK_HOLE for
full-size materialized inputs, no final symlink, stable descriptor/path
metadata and SHA-256. No 32-GiB evidence copy is required.

The existing service-fixture verifier retains its default behavior. The
shared rehash helper accepts a context label so direct-input errors are
distinguishable from service-input errors.

## Verification and boundary

`PYTHONPATH=tools python3 -B -m unittest -v
tools.largefile_acceptance_cases_test` passed 17/17. The new focused test
accepts a small external fixture without retaining its payload under the
evidence root, then rejects missing/changed after evidence, a substituted
report target, missing input-hash log, changed content, changed allocation,
wrong detection offset and wrong MaxFileSize reason. The existing service
input and materialized-edge rejection controls still pass. Relabelling the
small development control as Release fails the exact-edge check.
`sh tools/largefile_source_guards.sh` exited 0, including the 604-row case
map and empty-record-schema checks. `git diff --check` exited 0.

The missing next slice is a source-bound **producer/capture** that writes the
before identity before execution, runs the real scanner with an independent
oracle and measured resources, writes the after identity, and emits and
rechecks R04 records. No such record was produced here; the authoritative
acceptance-record file remains empty and no capability status was promoted.
Admission-gated daemon/PCRE work remains separately resource-blocked.

## Continuation: capture primitive

After Sonic1 connectivity returned, `tools/largefile_direct_input_capture.py`
was added to write and fsync the before identity **before** starting one direct
scanner command, then rehash and retain the after identity even when the
command cannot start. It refuses existing sidecars, symlinked inputs or
provenance directories, non-regular inputs, unstable input metadata and
non-materialized exact-edge inputs. The two records include the opened file's
device/inode and timestamps in addition to the R04 verifier's required
size, SHA-256, allocation and first-hole fields. A changed input fails closed;
the scanner's exit code is preserved, including expected detection/limit
exits, but this tool alone does not create an acceptance record.

`PYTHONPATH=tools PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest -v
tools.largefile_direct_input_capture_test tools.largefile_acceptance_cases_test`
passed 22/22. The sparse exact-edge control is rejected before hashing the
32-GiB logical range. The full source-guard suite also exited 0. No new
Sonic1 scan or capability promotion followed from these
local controls. The source-bound R04 producer, fresh package transfer/build,
and full qualification cases remain pending.

## Continuation: source-bound R04 producer

`tools/largefile_direct_input_capture.py` now requires an independent oracle
on its command-line path. It validates the expected input and case, outcome,
signature/offset, and staged source/build/config/database hashes **before**
starting the scanner, then retains the exact oracle bytes and a command-result
sidecar. The post-scan producer
`tools/largefile_direct_file_case_producer.py` requires those sidecars, the
structured report, log, resource row, and still-empty private temporary root.
It checks that the resource wrapper is named by the source-content manifest,
that the scanned executable hashes to the retained build identity, and that
the scanner invocation binds the database, report, input and size limits
without duplicate overrides. It then writes one R04 row and runs both the
generic case verifier and measured-resource binder/verifier. A small synthetic
development case and fail-closed controls pass locally; this is not Sonic1
scan evidence and cannot be relabeled Release.

State: `direct-file-verifier-capture-and-producer-locally-tested; fresh-source-live-case-pending`
