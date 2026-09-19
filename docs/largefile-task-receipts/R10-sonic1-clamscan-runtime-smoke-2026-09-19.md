# R10 — Sonic1 current-source clamscan runtime smoke

Date: 2026-09-19
Task ID / parent milestone: `R10` / CLI ingress

## Evidence identity

- Branch: `largefile-roadmap-qualification`
- Source commit: `1b514a79`
- Host: `sonic1`, login profile `sonic1-camera-key`
- Container: `clamav-current-7f3458c4`
- Container ID: `b46fa02bc4f4c6d9559ca20bebe97016a34610763fc7aa0af083e58b1ba173d0`
- Image: `clamav-32gb:dev-current`
- Image ID: `sha256:c0c10e2d6e6675c201dc657276543462de64896e53ae44cb9ba725a3a12d86df`
- Executable: `/tmp/clamav-7f3458c4-build/clamscan/clamscan`
- Database directory: `/src/unit_tests/input/other_sigs`
- Certificate directory: `/src/unit_tests/input/signing/verify`

The container provenance reported the rebuilt source bind mounted at `/src`.

## Runtime results

Version startup succeeded:

```text
ClamAV 1.5.3-largefile-devel
exit: 0
```

Clean-file scan succeeded with the checked-in test database:

```text
/src/README.md: OK
exit: 0
stderr: empty
```

The phishing control run used the checked-in phishing database directory and
three checked-in fixtures:

```text
/src/unit_tests/input/other_scanfiles/phish-test-ssl: OK
/src/unit_tests/input/other_scanfiles/phish-test-cloak: Heuristics.Phishing.Email.Cloaked.Null FOUND
/src/unit_tests/input/other_scanfiles/phish-test-clean: OK
exit: 1
```

The cloaked-phishing detection is the expected positive control. The SSL
fixture remains clean here because the full Python clamscan test creates a
temporary `H:example.com` phishing database entry; this smoke intentionally
used only retained repository database files and did not synthesize one.

## Boundary

This proves current-source `clamscan` startup, clean scanning, and a real
heuristic detection path in the disposable container. It is development smoke
evidence, not a complete R10 ingress matrix, daemon/milter/on-access proof,
R04 acceptance record, certified x86-64 qualification, or release evidence.

State: `development-verified`; qualification pending.
