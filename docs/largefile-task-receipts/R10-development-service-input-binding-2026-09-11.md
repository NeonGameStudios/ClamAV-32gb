# Task receipt: development service input binding

Task ID / parent milestone: `R04` / `R10` follow-up

Exact capability kind:id list: `clamd:SCANREPORT`,
`clamd:CONTSCANREPORT`, `clamd:MULTISCANREPORT`, `clamd:ALLMATCHSCANREPORT`,
`clamd:FILDESREPORT`, `clamd:INSTREAMREPORT`, `clamdscan:fdpass`, and
`clamdscan:stream`, each with clean, detection, and limit cases.

Starting commit and working-tree/source manifest identity:

- canonical source: `/Volumes/512gbNVME/github-external/ClamAV-32gb`
- branch: `largefile-roadmap-qualification`
- HEAD at capture: `b4cde643fce085fa016338339830b2b28ff9a42a`
- working tree was intentionally dirty and preserved
- capture source-manifest SHA-256: `4e860aee2a5110c4ec42720f18380d038bad9204f05fead90d92296d027282a4`

Prerequisites verified:

- current-source ARM64 development binaries were present in
  `/private/tmp/clamav-32gb-docker-build`
- repository test CA material was supplied from
  `unit_tests/input/signing/verify`
- runtime packages were installed only inside the disposable Docker
  container; no host software or remote server was used

Owned files and excluded shared files:

- owned: `tools/largefile_development_service_capture.py`, its focused test,
  and the matching source-guard assertions
- excluded: application/library behavior, the authoritative empty acceptance
  record, release readiness, and all certified-runner evidence

Observed failing case and expected behavior:

- the first current-source service capture produced daemon reports but the
  strict acceptance verifier rejected line 2 with
  `lifecycle-bound acceptance record lacks service input identity evidence`
- lifecycle-bound records must retain a versioned service-input identity
  sidecar whose fixture hash matches the record's named fixture role

Changes made:

- added `write_service_input_identity()` to record version-1 identities for
  the three small development fixtures, including path, size, SHA-256,
  allocation, and hole fields
- development service records now retain both
  `provenance/service-inputs-before.json` and
  `provenance/service-inputs-after.json`; the producer compares them before
  writing acceptance records
- added a focused regression for the sidecar schema and fixture hash binding
- added source guards for sidecar creation and mutation comparison

Commands, exits, logs and fixture hashes:

- `python3 -B largefile_development_service_capture_test.py`: exit 0,
  6/6 passed
- `python3 -B largefile_acceptance_cases_test.py`: exit 0, 12/12 passed
- current-source disposable service capture with `clamd` and `clamdscan`:
  exit 0, wrote 24 records
- independent host-side `validate_records(..., evidence_root=...)`: 24
  records accepted
- before/after sidecar SHA-256: `1da86c1cd30f20331e653f57d60d574c1c027986e1c92c7ef69e71986369eace`
- detection fixture SHA-256:
  `f60585c2f7f58a18184a7ee59b073ff4f5fc615531447294d8f2be3511abf843`
- limit fixture SHA-256:
  `6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326`
- daemon and client binary SHA-256:
  `dfa272199bffcab71bf20846942a2da836732b9a34e542e454dc5834c473dd8a`
  and `afb168092fe9538ccfcd0e525fb1c592a28b3eb448de2f3710c7acc31609d2ac`

Development tests passed:

- every direct structured report mode returned the expected clean,
  `DETECTION_TERMINATED`, or `LIMIT_INCOMPLETE` outcome
- `clamdscan --fdpass` and `clamdscan --stream` matched their report and exit
  contracts
- final `PONG`, PID-file presence, daemon exit, socket cleanup, and PID-file
  cleanup were retained for each outcome group
- the full tools suite afterward passed 145 tests with 2 expected skips

Full-size/certified evidence produced, or explicitly not run:

- no 32-GiB materialized input, production CVD, sanitizer, Linux x86-64,
  privileged fanotify, or release qualification evidence was produced
- the capture is ARM64 disposable development evidence only

Remaining failures / next slice:

- authoritative R04 records remain empty; all affected capabilities remain
  pending/bounded as before
- obtain the authorized Linux x86-64 runner and run the same sidecar-bound
  service producer against the reviewed full-size matrix

State: `development-verified`
