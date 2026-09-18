# R13 clamonacc report JSON publication boundary — 2026-09-17

## Scope

Harden the application-side structured-report publication helper used by
`clamonacc --report-json`. The helper now runs the payload through the shared
structured-status validator and alert validator before adding
`clamonacc_event_id` and serializing JSONL. Trailing bytes, duplicate
top-level keys, non-object payloads, contradictory completion/verdict pairs,
and infected reports without an exact alert name are therefore rejected at
the publication boundary instead of being rewritten into apparently
authoritative evidence.

The socket response path applies the same detection-alert requirement before
retaining a daemon frame. This keeps on-access detection handling aligned with
the daemon-side report consumer and prevents an alert-less detection from
being treated as a complete evidence record.

The boundary also rejects payload lengths above `UINT32_MAX` before passing the
length to the shared report API, and frees the parser's temporary alert value
on every exit path.

The on-access client header now includes `<stdio.h>` directly because its
public report-stream prototypes use `FILE *`; it no longer relies on an
indirect include from the context header.

## Verification

- `sh tools/largefile_inventory.sh` output matches
  `docs/largefile-inventory.tsv`.
- `git diff --check`: passed.
- `sh tools/largefile_source_guards.sh`: exit 0; all source, manifest,
  acceptance-contract, fixture, and evidence guards passed.
- No current-source clamonacc compile or runtime test was claimed: the local
  host lacks generated CMake metadata and the required OpenSSL/CURL/JSON-C
  development environment, while the authorized Sonic1 container still
  contains stale source and the durable current-source upload was denied by
  the MCP-SSH file-write policy.

This is source-level development verification only. It does not qualify
Linux x86-64 fanotify, service, sanitizer, full-size, or release evidence.

State: `development-verified; runtime-qualification-open`
